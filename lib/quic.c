#include "quic.h"
#include "packets.h"
#include "crypto.h"
#include <cutils/endian.h>
#include <cutils/char-array.h>
#include <assert.h>

enum qcrypto_level {
	QC_INITIAL,
	QC_HANDSHAKE,
	QC_PROTECTED,
};

enum qhandshake_state {
	QC_RUNNING,
	QC_PROCESS_SERVER_HELLO,
	QC_PROCESS_CERTIFICATE,
	QC_PROCESS_VERIFY,
	QC_PROCESS_FINISHED,
};

static const char prng_nonce[] = "quic-proxy prng nonce";

#define ALIGN_DOWN(type, u, sz) ((u) &~ ((type)(sz)-1))
#define ALIGN_UP(type, u, sz) ALIGN_DOWN(type, (u) + (sz) - 1, (sz))

int qc_init(qconnection_t *c, br_prng_seeder seedfn, void *pktbuf, size_t bufsz) {
	memset(c, 0, sizeof(*c));
	br_hmac_drbg_init(&c->rand, &br_sha256_vtable, prng_nonce, sizeof(prng_nonce));
	if (!seedfn || !seedfn(&c->rand.vtable)) {
		return -1;
	}

	uint8_t *p = (uint8_t*)ALIGN_UP(uintptr_t, (uintptr_t)pktbuf, 8);
	uint8_t *e = (uint8_t*)ALIGN_DOWN(uintptr_t, (uintptr_t)pktbuf + bufsz, 8);

	size_t pktnum = (e-p) / sizeof(qtx_packet_t);
	if (pktnum < 3 * QUIC_CRYPTO_PACKETS) {
		// insufficient buffer provided
		return -1;
	}

	qtx_packet_t *sent = (qtx_packet_t*)p;
	c->pkts[QC_INITIAL].sent = sent;
	c->pkts[QC_HANDSHAKE].sent = sent + QUIC_CRYPTO_PACKETS;
	c->pkts[QC_PROTECTED].sent = sent + 2 * QUIC_CRYPTO_PACKETS;

	c->pkts[QC_INITIAL].sent_len = QUIC_CRYPTO_PACKETS;
	c->pkts[QC_HANDSHAKE].sent_len = QUIC_CRYPTO_PACKETS;
	c->pkts[QC_PROTECTED].sent_len = pktnum - 2 * QUIC_CRYPTO_PACKETS;

	return 0;
}

static void generate_id(const br_prng_class **prng, uint8_t *id) {
	id[0] = DEFAULT_SERVER_ID_LEN;
	(*prng)->generate(prng, id+1, DEFAULT_SERVER_ID_LEN);
}

static void generate_ids(qconnection_t *c) {
	generate_id(&c->rand.vtable, &c->local_id);
	generate_id(&c->rand.vtable, &c->peer_id);
}

static void receive_packet(qpacket_buffer_t *s, uint64_t pktnum) {
	if (s->rx_next > 64 && pktnum < s->rx_next - 64) {
		// old packet - ignore
		return;
	}

	// check to see if we should move the receive window forward
	if (pktnum >= s->rx_next + 64) {
		// a long way
		s->received = 0;
		s->rx_next = pktnum + 1;
	} else if (pktnum >= s->rx_next) {
		// a short way
		size_t shift = (size_t)(s->rx_next - ALIGN_DOWN(uint64_t, s->rx_next, 64));
		uint64_t mask = UINT64_C(1) << (pktnum - s->rx_next);
		mask -= 1; // create a mask of n bits
		mask = (mask << shift) | (mask >> (64 - shift)); // and rotate around into place
		s->received &= ~mask; // and turn off the new bits
		s->rx_next = pktnum + 1;
	}

	s->received |= UINT64_C(1) << (pktnum & 63);
}

static int encode_ack_frame(qconnection_t *c, qslice_t *s, qpacket_buffer_t *pkts) {
	size_t ack_size = 1 + 8 + 1 + 1 + 1 + 2 * 16;
	if (s->p + ack_size > s->e) {
		return -1;
	}

	*(s->p++) = ACK;

	// largest acknowledged
	s->p = encode_varint(s->p, pkts->rx_next - 1);

	// ack delay - TODO
	*(s->p++) = 0;

	// block count - fill out later
	uint8_t *pblock_count = s->p++;
	size_t num_blocks = 0;
	size_t num_packets = 0;

	// rotate around such that the latest packet is in the top bit
	size_t shift = (size_t)(ALIGN_UP(uint64_t, pkts->rx_next, 64) - pkts->rx_next);
	uint64_t rx = (pkts->received << shift) | (pkts->received >> (64 - shift));

	// and shift the latest packet out
	rx <<= 1;

	// find the first block
	uint8_t first_block = 0;
	while (num_packets < 63 && (rx & UINT64_C(0x8000000000000000)) != 0) {
		first_block++;
		num_packets++;
		rx <<= 1;
	}
	*(s->p++) = first_block;

	while (rx != 0 && num_blocks < 16 && num_packets < 63) {
		// find the gap
		uint8_t gap = 0;
		while (num_packets < 63 && (rx & UINT64_C(0x8000000000000000)) == 0) {
			gap++;
			num_packets++;
			rx <<= 1;
		}

		// find the block
		uint8_t block = 0;
		while (num_packets < 63 && (rx & UINT64_C(0x8000000000000000)) != 0) {
			block++;
			num_packets++;
			rx <<= 1;
		}

		*(s->p++) = gap;
		*(s->p++) = block;
		num_blocks++;
	}

	*pblock_count = (uint8_t)num_blocks;
	return 0;
}

static int start_long_packet(qconnection_t *c, enum qcrypto_level level, qslice_t s, qslice_t *data) {

	size_t hsz = 1;
	hsz += 4; // version
	hsz += 1 + c->peer_id[0] + c->local_id[0];
	if (level == QC_INITIAL) {
		hsz++; // token
	}
	hsz += 2; // length;
	hsz += packet_number_length(c->pkts[level].tx_next);

	size_t fsz = QUIC_TAG_SIZE;

	data->p = s.p + hsz;
	data->e = s.e - fsz;
	
	return (data->p < data->e) ? 0 : -1;
}

static qtx_packet_t *finish_long_packet(qconnection_t *c, enum qcrypto_level level, qslice_t *s, qslice_t *data, size_t minsz) {
	static const uint8_t headers[] = {
		INITIAL_PACKET,
		HANDSHAKE_PACKET,
		PROTECTED_PACKET,
	};

	qpacket_buffer_t *pkts = &c->pkts[level];
	uint8_t *pkt_begin = s->p;

	// padding
	size_t pkt_sz = (size_t)(data->p - pkt_begin) + QUIC_TAG_SIZE;
	if (pkt_sz < minsz) {
		size_t pad = minsz - pkt_sz;
		memset(data->p, PADDING, pad);
		data->p += pad;;
	}

	// header
	*(s->p++) = headers[level];
	s->p = write_big_32(s->p, QUIC_VERSION);

	// connection IDs
	*(s->p++) = (encode_id_len(c->peer_id[0]) << 4) | encode_id_len(c->local_id[0]);
	s->p = append(s->p, c->peer_id + 1, c->peer_id[0]);
	s->p = append(s->p, c->local_id + 1, c->local_id[0]);

	// token
	if (level == QC_INITIAL) {
		*(s->p++) = 0;
	}

	// length
	size_t data_sz = (size_t)(data->p + QUIC_TAG_SIZE - s->p);
	s->p = write_big_16(s->p, (uint16_t)data_sz);

	// packet number
	uint8_t *packet_number = s->p;
	s->p = encode_packet_number(s->p, pkts->tx_next);
	uint8_t *enc_begin = s->p;

	// tag
	uint8_t *tag = data->p;
	s->p = data->p + QUIC_TAG_SIZE;

	const qcipher_class **cipher = &pkts->tkey.u.vtable;
	(*cipher)->encrypt(cipher, pkts->tx_next, pkts->tkey.data_iv, pkt_begin, enc_begin, tag);
	(*cipher)->protect(cipher, packet_number, 2, data_sz);

	return &pkts->sent[(pkts->tx_next++) % pkts->sent_len];
}

static qtx_packet_t *encode_crypto_packet(qconnection_t *c, qslice_t *s, enum qcrypto_level level, uint32_t off, const void *data, size_t sz, size_t minsz) {
	qslice_t p;
	if (start_long_packet(c, level, *s, &p)) {
		return -1;
	}
	qpacket_buffer_t *pkts = &c->pkts[level];
	if (pkts->rx_next && encode_ack_frame(c, &p, pkts)) {
		return -1;
	}

	size_t chdr = 1 + 4 + 4;
	if (p.p + chdr > p.e) {
		return -1;
	}
	size_t tocopy = (size_t)(p.e - p.p) - chdr;
	*(p.p++) = CRYPTO;
	p.p = encode_varint(p.p, off);
	p.p = encode_varint(p.p, tocopy);
	p.p = append(p.p, data, tocopy);

	qtx_packet_t *pkt = finish_long_packet(c, level, s, &p, minsz);
	pkt->stream = NULL;
	pkt->from = off;
	pkt->to = off + tocopy;
	return pkt;
}


int qc_connect(qconnection_t *c, const char *server_name, const br_x509_class **validator, const qcrypto_params_t *params) {
	c->params = params;
	c->server_name = server_name;
	c->validator = validator;
	c->is_client = true;
	c->crypto_state = QC_PROCESS_SERVER_HELLO;
	c->rx_crypto.state = 0;
	c->rx_crypto_off = 0;
	c->rand.vtable->generate(&c->rand.vtable, c->client_random, sizeof(c->client_random));
	generate_ids(c);

	qpacket_buffer_t *init = &c->pkts[QC_INITIAL];
	generate_initial_secrets(c->peer_id, &init->tkey, &init->rkey);

	// generate a private key for the high priority groups
	const br_ec_impl *ec = br_ec_get_default();
	uint8_t pub_keys[QUIC_MAX_KEYSHARE][BR_EC_KBUF_PUB_MAX_SIZE];
	c->key_num = MIN(QUIC_MAX_KEYSHARE, strlen(params->groups));
	for (size_t i = 0; i < c->key_num; i++) {
		if (!br_ec_keygen(&c->rand.vtable, ec, &c->keys[i], c->key_data[i], params->groups[i])) {
			return -1;
		}
	}

	// encode the TLS record
	uint8_t tlsbuf[1024];
	qslice_t tls = { tlsbuf, tlsbuf + sizeof(tlsbuf) };
	if (encode_client_hello(c, &tls)) {
		return -1;
	}


	// encode the UDP packet
	uint8_t udpbuf[DEFAULT_PACKET_SIZE];
	qslice_t udp = { udpbuf, udpbuf + sizeof(udpbuf) };
	qtx_packet_t *pkt = encode_crypto_packet(c, &udp, QC_INITIAL, 0, tlsbuf, (size_t)(tls.p - tlsbuf), 1200);
	if (pkt == NULL) {
		return -1;
	}

	// send it
	return c->send(c->send_user, udpbuf, (size_t)(udp.p - udpbuf), &pkt->sent);
}

static void log_key(qconnection_t *c, const char *label, const uint8_t *secret, size_t len) {
	static const char hex[] = "0123456789abcdef";
	char sec_hex[2 * QUIC_MAX_HASH_SIZE + 1];
	char rand_hex[2 * QUIC_RANDOM_SIZE + 1];
	for (size_t i = 0; i < QUIC_RANDOM_SIZE; i++) {
		rand_hex[2 * i] = hex[c->client_random[i] >> 4];
		rand_hex[2 * i + 1] = hex[c->client_random[i] & 15];
	}
	rand_hex[2 * QUIC_RANDOM_SIZE] = 0;
	for (size_t i = 0; i < len; i++) {
		sec_hex[2 * i] = hex[secret[i] >> 4];
		sec_hex[2 * i + 1] = hex[secret[i] & 15];
	}
	sec_hex[2 * len] = 0;
	LOG(c->keylog, "%s %s %s\n", label, sec_hex, rand_hex);
}

static const qsignature_class *get_signature(const qsigner_class **signer, uint64_t client_mask) {
	for (size_t i = 0;; i++) {
		const qsignature_class *c = (*signer)->get_type(signer, i);
		if (!c) {
			break;
		}
		if ((UINT64_C(1) << c->curve) & client_mask) {
			return c;
		}
	}
	return NULL;
}

int qc_accept(qconnection_t *c, const qconnect_request_t *h, const qsigner_class **signer) {
	// general setup
	memcpy(c->peer_id, h->source, QUIC_ADDRESS_SIZE);
	memcpy(c->local_id, h->destination, QUIC_ADDRESS_SIZE);
	c->crypto_state = QC_WAIT_FOR_FINISHED;
	c->rx_crypto_off = 0;
	c->is_client = false;

	// nonces
	memcpy(c->client_random, h->random, QUIC_RANDOM_SIZE);
	c->rand.vtable->generate(&c->rand.vtable, c->server_random, QUIC_RANDOM_SIZE);

	// cipher
	c->cipher = h->cipher;

	// key group
	c->key_num = 1;
	if (!h->key.curve || !br_ec_keygen(&c->rand.vtable, br_ec_get_default(), &c->keys[0], c->key_data[0], h->key.curve)) {
		return -1;
	}

	// certificates
	c->signature = get_signature(signer, h->signatures);
	if (!c->signature) {
		return -1;
	}
	c->validator = NULL;
	c->signer = signer;
	c->server_name = NULL;
	c->params = NULL;

	// transcript
	const br_hash_class *hash = c->cipher->hash;
	hash->init(&c->msg_hash.vtable);
	hash->update(&c->msg_hash.vtable, h->raw, h->raw_size);

	// server hello
	uint8_t tlsbuf[3 * 1024];
	qslice_t s = { tlsbuf, tlsbuf + sizeof(tlsbuf) };
	if (encode_server_hello(c, &s)) {
		return -1;
	}
	size_t init_len = (size_t)(s.p - tlsbuf);
	hash->update(&c->msg_hash.vtable, tlsbuf, init_len);

	// now that we have both the hellos in the msg hash, we can generate the handshake keys
	qpacket_buffer_t *hs = &c->pkts[QC_HANDSHAKE];
	if (generate_handshake_secrets(c->cipher, &c->msg_hash.vtable, &h->key, &c->keys[0], &hs->rkey, &hs->tkey, c->master_secret)) {
		return -1;
	}

	// Certificate
	uint8_t *cert_begin = s.p;
	if (encode_certificates(&s, signer)) {
		return -1;
	}
	hash->update(&c->msg_hash.vtable, cert_begin, s.p - cert_begin);

	// CertificateVerify
	uint8_t verify[QUIC_MAX_CERT_VERIFY_SIZE];
	size_t vlen = generate_cert_verify(c->is_client, &c->msg_hash.vtable, verify);
	uint8_t sig[QUIC_MAX_SIG_SIZE];
	uint8_t *verify_begin = s.p;
	int slen = (*signer)->sign(signer, c->signature, verify, vlen, sig);
	if (slen < 0 || encode_verify(&s, c->signature, sig, (size_t)slen)) {
		return -1;
	}
	hash->update(&c->msg_hash.vtable, verify_begin, s.p - verify_begin);

	// Finished
	uint8_t fin[QUIC_MAX_HASH_SIZE];
	size_t flen = generate_finish_verify(&hs->tkey, &c->msg_hash.vtable, fin);
	uint8_t *finish_begin = s.p;
	if (encode_finished(&s, fin, flen)) {
		return -1;
	}
	hash->update(&c->msg_hash.vtable, finish_begin, s.p - finish_begin);
	size_t hs_len = (size_t)(s.p - tlsbuf) - init_len;

	qpacket_buffer_t *prot = &c->pkts[QC_PROTECTED];
	generate_protected_secrets(c->cipher, &c->msg_hash.vtable, c->master_secret, &prot->rkey, &prot->tkey);

	// encode and sent it
	size_t init_sent = 0;
	size_t hs_sent = 0;
	while (init_sent < init_len && hs_sent < hs_len) {
		uint8_t udpbuf[DEFAULT_PACKET_SIZE];
		qslice_t udp = { udpbuf, udpbuf + sizeof(udpbuf) };
		qtx_packet_t *pkts[2] = { NULL, NULL };
		if (init_sent < init_len) {
			pkts[0] = encode_crypto_packet(c, &udp, QC_INITIAL, init_sent, tlsbuf + init_sent, init_len - init_sent, 0);
			if (pkts[0]) {
				init_sent = (size_t) pkts[0]->to;
			}
		}
		if (hs_sent < hs_len) {
			pkts[1] = encode_crypto_packet(c, &udp, QC_HANDSHAKE, hs_sent, tlsbuf + init_len + hs_sent, hs_len - hs_sent, 0);
			if (pkts[1]) {
				hs_sent = (size_t)pkts[1]->to;
			}
		}
		tick_t txtime;
		if (c->send(c->send_user, udpbuf, (size_t)(udp.p - udpbuf), &txtime)) {
			return -1;
		}
		if (pkts[0]) {
			pkts[0]->sent = txtime;
		}
		if (pkts[1]) {
			pkts[1]->sent = txtime;
		}
	}
	
	return 0;
}

static const qcipher_class *find_cipher(uint16_t code, const qcipher_class *const *ciphers) {
	while (*ciphers) {
		if ((*ciphers)->cipher == code) {
			return *ciphers;
		}
		ciphers++;
	}
	return NULL;
}

static const br_ec_private_key *find_private_key(qconnection_t *c, uint16_t curve) {
	for (size_t i = 0; i < c->key_num; i++) {
		if (c->keys[i].curve == curve) {
			return &c->keys[i];
		}
	}
	return NULL;
}

static int process_server_hello(qconnection_t *c, const struct server_hello *h, qslice_t record) {
	// crypto management
	memcpy(c->server_random, h->random, QUIC_RANDOM_SIZE);

	// cipher
	c->cipher = find_cipher(h->cipher, c->params->ciphers);
	if (!c->cipher) {
		return -1;
	}

	// key groups
	const br_ec_private_key *sk = find_private_key(c, h->key.curve);
	if (!sk) {
		return -1;
	}

	uint8_t chello[1024];
	qslice_t s = { chello, chello + sizeof(chello) };
	encode_client_hello(c, &s);

	// update the transcript now that we know what hash to use
	const br_hash_class *hash = c->cipher->hash;
	hash->init(&c->msg_hash.vtable);
	hash->update(&c->msg_hash.vtable, chello, s.p - chello);
	hash->update(&c->msg_hash.vtable, record.p, record.e - record.p);

	qpacket_buffer_t *hs = &c->pkts[QC_HANDSHAKE];
	return generate_handshake_secrets(c->cipher, &c->msg_hash.vtable, &h->key, sk, &hs->tkey, &hs->rkey, c->master_secret);
}

static const qsignature_class *find_signature(uint16_t code, const qsignature_class *const *signatures) {
	while (*signatures) {
		if ((*signatures)->algorithm == code) {
			return *signatures;
		}
		signatures++;
	}
	return NULL;
}

static int process_verify(qconnection_t *c, const struct verify *v) {
	const qsignature_class *type = find_signature(v->algorithm, c->params->signatures);
	if (!type) {
		return -1;
	}

	uint8_t verify[QUIC_MAX_CERT_VERIFY_SIZE];
	size_t vlen = generate_cert_verify(c->msg_hash.vtable, !c->is_client, v->msg_hash, verify);
	const br_x509_pkey *pk = (*c->validator)->get_pkey(c->validator, NULL);
	return type->verify(type, pk, verify, vlen, v->signature, v->sig_size);
}

static int process_finished(qconnection_t *c, const struct finished *fin) {
	qpacket_buffer_t *hs = &c->pkts[QC_HANDSHAKE];
	uint8_t verify[QUIC_MAX_HASH_SIZE];
	size_t vlen = generate_finish_verify(&hs->rkey, fin->msg_hash, verify);
	if (vlen != fin->size || memcmp(fin->verify, verify, vlen)) {
		return -1;
	}

	if (c->is_client) {
		qpacket_buffer_t *prot = &c->pkts[QC_PROTECTED];
		generate_protected_secrets(c->cipher, &c->msg_hash.vtable, c->master_secret, &prot->tkey, &prot->rkey);

		uint8_t msg_hash[QUIC_MAX_HASH_SIZE];
		c->msg_hash.vtable->out(&c->msg_hash.vtable, msg_hash);

		// Finished
		uint8_t tls[256];
		qslice_t s = { tls, tls + sizeof(tls) };
		vlen = generate_finish_verify(&hs->tkey, msg_hash, verify);
		if (encode_finished(&s, verify, vlen)) {
			return -1;
		}
		// add the client finished to the hash
		c->msg_hash.vtable->update(&c->msg_hash.vtable, tls, s.p - tls);

		// send it
		uint8_t udpbuf[512];
		qslice_t udp = { udpbuf, udpbuf + sizeof(udpbuf) };
		qtx_packet_t *pkt = encode_crypto_packet(c, &udp, QC_HANDSHAKE, 0, tls, s.p - tls, 0);
		if (!pkt || c->send(c->send_user, udpbuf, udp.p - udpbuf, &pkt->sent)) {
			return -1;
		}
	}
	return 0;
}

static int decode_ack(qpacket_buffer_t *b, qslice_t *s) {
	int64_t largest = decode_varint(s);
	int64_t delay = decode_varint(s);
	int64_t count = decode_varint(s);
	int64_t first = decode_varint(s);
	(void)delay;
	(void)largest;
	if (first < 0) {
		return -1;
	}

	while (count) {
		int64_t gap = decode_varint(s);
		int64_t block = decode_varint(s);
		(void)gap;
		if (block < 0) {
			return -1;
		}
		count--;
	}

	return 0;
}

static uint8_t *find_non_padding(uint8_t *p, uint8_t *e) {
	while (p < e && *p == PADDING) {
		p++;
	}
	return p;
}

static enum qcrypto_level expected_level(int crypto_state) {
	switch (crypto_state) {
	case QC_PROCESS_SERVER_HELLO:
		return QC_INITIAL;
	case QC_PROCESS_CERTIFICATE:
	case QC_PROCESS_VERIFY:
	case QC_PROCESS_FINISHED:
		return QC_HANDSHAKE;
	default:
		return QC_PROTECTED;
	}
}

static int decode_crypto(qconnection_t *c, enum qcrypto_level level, qslice_t *s) {
	int64_t off = decode_varint(s);
	int64_t len = decode_varint(s);
	if (len < 0 || (s->e - s->p) < len) {
		goto err;
	}
	qslice_t tls = { s->p, s->p + len };
	s->p = tls.e;
	if (level != expected_level(c->crypto_state)) {
		// probably a resend of old data
		return 0;
	} else if (off != c->rx_crypto_off) {
		goto err;
	}
	c->rx_crypto_off += len;

	const br_hash_class **msgs = &c->msg_hash.vtable;
	struct crypto_decoder *d = &c->rx_crypto;

	switch (c->crypto_state) {
	case QC_PROCESS_SERVER_HELLO: {
		int r = decode_server_hello(d, &c->rx_crypto_data.server_hello, (unsigned)off, tls.p, tls.e - tls.p);
		if (r < 0) {
			goto err;
		} else if (!r) {
			// TODO support partial server hellos
			// transcript hash doesn't support this
			goto err;
		}
		qslice_t record = { tls.p, tls.p + r };
		off += r;
		tls.p += r;
		if (process_server_hello(c, &c->rx_crypto_data.server_hello, record)) {
			goto err;
		}
		c->crypto_state = QC_PROCESS_CERTIFICATE;
		d->state = 0;
		(*c->validator)->start_chain(c->validator, c->server_name);
		c->rx_crypto_off = 0;
		return 0;
	}
	case QC_PROCESS_CERTIFICATE: {
		int r = decode_certificates(d, c->validator, (unsigned)off, tls.p, tls.e - tls.p);
		if (r < 0) {
			goto err;
		} else if (!r) {
			(*msgs)->update(msgs, tls.p, tls.e - tls.p);
			return 0;
		}
		(*msgs)->update(msgs, tls.p, r);
		off += r;
		tls.p += r;
		if ((*c->validator)->end_chain(c->validator)) {
			goto err;
		}
		c->crypto_state = QC_PROCESS_VERIFY;
		d->state = 0;
		(*msgs)->out(msgs, c->rx_crypto_data.verify.msg_hash);
	}
	case QC_PROCESS_VERIFY: {
		int r = decode_verify(d, &c->rx_crypto_data.verify, (unsigned)off, tls.p, tls.e - tls.p);
		if (r < 0) {
			goto err;
		} else if (!r) {
			(*msgs)->update(msgs, tls.p, tls.e - tls.p);
			return 0;
		}
		(*msgs)->update(msgs, tls.p, r);
		off += r;
		tls.p += r;
		if (process_verify(c, &c->rx_crypto_data.verify)) {
			goto err;
		}
		c->crypto_state = QC_PROCESS_FINISHED;
		d->state = 0;
		(*msgs)->out(msgs, c->rx_crypto_data.finished.msg_hash);
	}
	case QC_PROCESS_FINISHED: {
		int r = decode_finished(d, &c->rx_crypto_data.finished, (unsigned)off, tls.p, tls.e - tls.p);
		if (r < 0) {
			goto err;
		} else if (!r) {
			(*msgs)->update(msgs, tls.p, tls.e - tls.p);
			return 0;
		}
		(*msgs)->update(msgs, tls.p, r);
		off += r;
		tls.p += r;
		if (process_finished(c, &c->rx_crypto_data.finished)) {
			goto err;
		}
		c->crypto_state = QC_RUNNING;
		return 0;
	}
	case QC_RUNNING:
		// TODO - process runtime crypto data
		return 0;
	default:
		goto err;
	}
err:
	// on error we drop the whole packet
	// TODO - better error handling
	return -1;
}

static int process_protected(qconnection_t *c, qslice_t s) {
	// TODO
	return 0;
}

static int process_packet(qconnection_t *c, qslice_t s, enum qcrypto_level level) {
	if (level == QC_PROTECTED) {
		return process_protected(c, s);
	}
	qpacket_buffer_t *pkts = &c->pkts[level];
	while (s.p < s.e) {
		switch (*(s.p++)) {
		default:
			return -1;
		case PADDING:
			s.p = find_non_padding(s.p, s.e);
			break;
		case ACK:
			if (decode_ack(pkts, &s)) {
				return -1;
			}
			break;
		case CRYPTO:
			if (decode_crypto(c, level, &s)) {
				return -1;
			}
			break;
		}
	}
	return 0;
}

int qc_get_destination(void *buf, size_t len, uint8_t *out) {
	uint8_t *u = buf;
	if (!len) {
		return -1;
	}
	uint8_t *pid;
	uint8_t dcil;
	if (*u & LONG_HEADER_FLAG) {
		if (len < 6) {
			return -1;
		}
		if (big_32(u + 1) != QUIC_VERSION) {
			return -2;
		}
		dcil = decode_id_len(u[5] >> 4);
		if (len < 6 + dcil) {
			return -1;
		}
		pid = u + 6;
	} else {
		if (len < 1 + DEFAULT_SERVER_ID_LEN) {
			return -1;
		}
		dcil = DEFAULT_SERVER_ID_LEN;
		pid = u + 1;
	}

	out[0] = dcil;
	memcpy(out + 1, u + 6, dcil);
	memset(out + 1 + dcil, 0, QUIC_ADDRESS_SIZE - dcil);
	return 0;
}

int qc_recv(qconnection_t *c, void *buf, size_t len, tick_t rxtime) {
	qslice_t s;
	s.p = buf;
	s.e = s.p + len;

	while (s.p < s.e) {
		uint8_t *pkt_begin = s.p;
		uint8_t hdr = *(s.p++);
		if (hdr & LONG_HEADER_FLAG) {
			if (s.e - s.p < 5) {
				return -1;
			}
			uint32_t version = big_32(s.p);
			s.p += 4;
			if (version != QUIC_VERSION) {
				// remotes shouldn't randomly change the version on us
				return -1;
			}
			// skip over ids
			uint8_t dcil = decode_id_len(s.p[0] >> 4);
			uint8_t scil = decode_id_len(s.p[0] & 0xF);
			s.p++;
			s.p += dcil + scil;

			enum qcrypto_level level;

			switch (hdr) {
			case INITIAL_PACKET: {
				level = QC_INITIAL;
				int64_t toksz = decode_varint(&s);
				if (toksz < 0 || toksz >(int64_t)(s.e - s.p)) {
					return -1;
				}
				s.p += (size_t)toksz; // skip over token
				break;
			}
			case HANDSHAKE_PACKET:
				level = QC_HANDSHAKE;
				break;
			case PROTECTED_PACKET:
				level = QC_PROTECTED;
				break;
			default:
				// TODO handle RETRY
				return -1;
			}

			int64_t paysz = decode_varint(&s);
			if (paysz < 0 || paysz > (int64_t)(s.e - s.p)) {
				return -1;
			}
			uint8_t *packet_number = s.p;
			s.p += paysz;

			qslice_t data;
			qpacket_buffer_t *pkts = &c->pkts[level];
			int64_t pktnum = decrypt_packet(&pkts->rkey, pkt_begin, packet_number, s.p, &data);

			if (pktnum >= 0 && !process_packet(c, data, level)) {
				// only mark the packet as received if we could successfully process it
				receive_packet(pkts, pktnum);
			}

		} else {
			// short header
			s.p += DEFAULT_SERVER_ID_LEN;
			if (s.p > s.e) {
				return -1;
			}
			qslice_t data;
			int64_t pktnum = decrypt_packet(&c->pkts[QC_PROTECTED].rkey, pkt_begin, s.p, s.e, &data);
			if (pktnum < 0) {
				return -1;
			}

			return process_protected(c, data);
		}
	}

	return 0;
}
