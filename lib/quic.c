#include "quic.h"
#include "packets.h"
#include "crypto.h"
#include <cutils/endian.h>
#include <cutils/char-array.h>
#include <assert.h>


static const char prng_nonce[] = "quic-proxy prng nonce";


static const uint8_t def_ciphers[] = { 0x13, 0x01 };
static const uint8_t def_groups[] = { 0x00, 0x1D };
static const uint8_t def_algorithms[] = { 0x04, 0x01 };

#define ALIGN_DOWN(type, u, sz) ((u) &~ ((type)(sz)-1))
#define ALIGN_UP(type, u, sz) ALIGN_DOWN(type, (u) + (sz) - 1, (sz))

static void setup_level(qpacket_buffer_t *b, qtx_packet_t *sent, size_t sent_len) {
	b->sent = sent;
	b->sent_len = sent_len;

	b->tx_crypto.id = -1;
	b->tx_crypto.data = b->tx_crypto_buf;
	b->tx_crypto.max_data_allowed = UINT64_MAX;

	b->rx_crypto.id = -1;
	b->rx_crypto.data = b->rx_crypto_buf;
	b->rx_crypto.valid = b->rx_crypto_valid;
	b->rx_crypto.len = sizeof(b->rx_crypto_buf);
}

int qc_init(qconnection_t *c, br_prng_seeder seedfn, void *pktbuf, size_t bufsz) {
	memset(c, 0, sizeof(*c));
	br_hmac_drbg_init(&c->rand, &br_sha256_vtable, prng_nonce, sizeof(prng_nonce));
	if (!seedfn || !seedfn(&c->rand.vtable)) {
		return -1;
	}
	c->ciphers.p = (uint8_t*)def_ciphers;
	c->ciphers.e = c->ciphers.p + sizeof(def_ciphers);
	c->groups.p = (uint8_t*)def_groups;
	c->groups.e = c->groups.p + sizeof(def_groups);
	c->algorithms.p = (uint8_t*)def_algorithms;
	c->algorithms.e = c->algorithms.p + sizeof(def_algorithms);
	c->peer_addr = &c->peer_addrs[0];

	uint8_t *p = (uint8_t*)ALIGN_UP(uintptr_t, (uintptr_t)pktbuf, 8);
	uint8_t *e = (uint8_t*)ALIGN_DOWN(uintptr_t, (uintptr_t)pktbuf + bufsz, 8);

	size_t pktnum = (e-p) / sizeof(qtx_packet_t);
	if (pktnum < 3 * QUIC_CRYPTO_PACKETS) {
		// insufficient buffer provided
		return -1;
	}

	qtx_packet_t *sent = (qtx_packet_t*)p;
	setup_level(&c->pkts[QC_INITIAL], sent, QUIC_CRYPTO_PACKETS);
	setup_level(&c->pkts[QC_HANDSHAKE], sent + QUIC_CRYPTO_PACKETS, QUIC_CRYPTO_PACKETS);
	setup_level(&c->pkts[QC_PROTECTED], sent + 2 * QUIC_CRYPTO_PACKETS, pktnum - (2 * QUIC_CRYPTO_PACKETS));

	return 0;
}

void qc_on_accept(qconnection_t *c, const struct sockaddr *sa, size_t sasz) {
	for (int i = 0; i < QUIC_MAX_ADDR; i++) {
		if (!c->peer_addrs[i].len) {
			memcpy(&c->peer_addrs[i].ss, sa, sasz);
			c->peer_addrs[i].len = sasz;
			break;
		}
	}
}

static int lookup_peer_name(qconnection_t *c, int family, const char *server_name, const char *svc_name) {
	if (ca_set(&c->server_name, server_name)) {
		return -1;
	}

	struct addrinfo hints, *result;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = (family == AF_INET6 ? AI_V4MAPPED : 0);
	if (getaddrinfo(server_name, svc_name, &hints, &result)) {
		return -1;
	}

	for (struct addrinfo *rp = result; rp != NULL; rp = rp->ai_next) {
		qc_on_accept(c, rp->ai_addr, rp->ai_addrlen);
	}

	freeaddrinfo(result);
	return 0;
}

static void generate_id(const br_prng_class **prng, qconnection_id_t *id) {
	id->len = DEFAULT_SERVER_ID_LEN;
	(*prng)->generate(prng, id->id, DEFAULT_SERVER_ID_LEN);
}

static void generate_ids(qconnection_t *c) {
	for (int i = 0; i < QUIC_MAX_IDS; i++) {
		if (!c->local_ids[i].len) {
			generate_id(&c->rand.vtable, &c->local_ids[i]);
		}
	}
	if (!c->local_id) {
		c->local_id = &c->local_ids[0];
	}
	if (!c->peer_id) {
		generate_id(&c->rand.vtable, &c->peer_ids[0]);
		c->peer_id = &c->peer_ids[0];
	}
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

static int receive_data(qrx_stream_t *s, uint64_t offset, const uint8_t *data, size_t len) {
	if (offset + len > s->offset + s->len) {
		// flow control error
		return -1;
	} else if (offset + len < s->offset) {
		// old data
		return 0;
	}

	if (offset < s->offset) {
		// old start, but runs into new territory
		size_t behind = (size_t)(s->offset - offset);
		data += behind;
		len -= behind;
	}

	// copy the data
	memcpy(s->data + offset - s->offset, data, len);

	// start setting bits - s->offset may not be aligned
	size_t i = (size_t)(offset - ALIGN_DOWN(uint64_t, s->offset, 32));
	size_t end = (size_t)(offset - s->offset) + len;
	size_t align_begin = ALIGN_UP(size_t, i, 32);
	size_t align_end = ALIGN_DOWN(size_t, end, 32);

	// update the bits leading in
	while (i < align_begin) {
		s->valid[i >> 5] |= 1U << (i & 31);
		i++;
	}

	// update the aligned middle
	while (i < align_end) {
		s->valid[i >> 5] = UINT32_C(0xFFFFFFFF);
		i += 32;
	}

	// update the bits leading out
	while (i < end) {
		s->valid[i >> 5] |= 1U << (i & 31);
		i++;
	}

	// move the base and pointers forward

	// deal with an unaligned base
	if (*s->valid == UINT32_C(0xFFFFFFFF) && (s->offset & 31)) {
		uint64_t new_offset = ALIGN_UP(uint64_t, s->offset, 32);
		s->data += new_offset - s->offset;
		s->valid++;
		s->offset = new_offset;
	}

	// move the pointer forward in the aligned middle chunk
	while (*s->valid == UINT32_C(0xFFFFFFFF)) {
		s->data += 32;
		s->offset += 32;
		s->len -= 32;
		s->valid++;
	}

	// deal with the unaligned tail
	size_t shift = (size_t)(s->offset - ALIGN_DOWN(uint64_t, s->offset, 32));
	uint32_t valid = *s->valid >> shift;
	while (valid & 1) {
		s->data++;
		s->offset++;
		s->len--;
		valid >>= 1;
	}

	return 0;
}

static qtx_packet_t *encode_long_packet(qconnection_t *c, qslice_t *s, enum qcrypto_level level, qtx_stream_t *tx, uint64_t from, uint64_t to, bool include_padding) {
	static uint8_t headers[QC_NUM_LEVELS] = {
		INITIAL_PACKET,
		HANDSHAKE_PACKET,
		PROTECTED_PACKET,
	};

	size_t hdr_size = 1 + 4 + 1 + c->peer_id->len + c->local_id->len + 1 + 2 + 4;
	size_t ack_size = 1 + 8 + 1 + 1 + 1 + 2 * 16;
	size_t frame_size = 1 + 8 + 8 + 1;
	if (s->p + hdr_size + ack_size + frame_size + QUIC_TAG_SIZE > s->e) {
		return NULL;
	}

	qpacket_buffer_t *pkts = &c->pkts[level];

	// header
	uint8_t *pkt_begin = s->p;
	*(s->p++) = headers[level];
	s->p = write_big_32(s->p, QUIC_VERSION);

	// connection IDs
	*(s->p++) = (encode_id_len(c->peer_id->len) << 4) | encode_id_len(c->local_id->len);
	s->p = append(s->p, c->peer_id->id, c->peer_id->len);
	s->p = append(s->p, c->local_id->id, c->local_id->len);

	// token
	if (level == QC_INITIAL) {
		*(s->p++) = 0;
	}

	// length
	s->p += 2; // fill out later

	// packet number
	uint8_t *packet_number = s->p;
	s->p = encode_packet_number(s->p, pkts->tx_next);
	uint8_t *enc_begin = s->p;

	if (pkts->rx_next) {
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
	}

	if (tx && to > from) {
		uint64_t max = from + (s->e - (s->p + 1 + 8 + 8 + QUIC_TAG_SIZE));
		if (to > max) {
			to = max;
		}
		size_t len = (size_t)(to - from);
		*(s->p++) = (tx->id < 0) ? CRYPTO : (STREAM | STREAM_OFF_FLAG | STREAM_LEN_FLAG);
		s->p = encode_varint(s->p, from);
		s->p = encode_varint(s->p, len);
		s->p = append(s->p, tx->data + (size_t)(from - tx->offset), len);
	}

	if (true) {//if (include_padding) {
		size_t pad = s->e - (s->p + QUIC_TAG_SIZE);
		memset(s->p, PADDING, pad);
		s->p += pad;
	}

	s->p += QUIC_TAG_SIZE;
	write_big_16(packet_number - 2, VARINT_16 | (uint16_t)(s->p - packet_number));
	encrypt_packet(&pkts->tkey, pkts->tx_next, pkt_begin, packet_number, enc_begin, s->p);

	// register packet in tx buffer
	qtx_packet_t *pkt = &pkts->sent[pkts->tx_next % pkts->sent_len];
	pkt->from = from;
	pkt->to = to;
	pkt->stream = tx;
	pkt->sent = 0;
	pkts->tx_next++;
	return pkt;
}

static int send_long_packets(qconnection_t *c, enum qcrypto_level level, qtx_stream_t *tx, uint64_t from, uint64_t to) {
	while (from < to) {
		uint8_t buf[DEFAULT_PACKET_SIZE];
		qslice_t s = { buf, buf + sizeof(buf) };
		qtx_packet_t *pkt = encode_long_packet(c, &s, level, tx, from, to, false);
		if (!pkt || c->send(c->user, buf, s.p - buf, (struct sockaddr*)&c->peer_addr->ss, c->peer_addr->len, &pkt->sent)) {
			return -1;
		}
		from = pkt->to;
	}
	return 0;
}

int qc_connect(qconnection_t *c, int family, const char *host_name, const char *svc_name) {
	qpacket_buffer_t *pkts = &c->pkts[QC_INITIAL];
	qtx_stream_t *tx = &pkts->tx_crypto;

	c->hs_state = QC_WAIT_FOR_SERVER_HELLO;
	c->is_client = true;
	if (lookup_peer_name(c, family, host_name, svc_name)) {
		return -1;
	}

	// generate the initial keys
	generate_ids(c);
	generate_initial_secrets(c->peer_id, &pkts->tkey, &pkts->rkey);

	// setup the client hello
	struct client_hello ch;
	ch.server_name.p = (uint8_t*)c->server_name.c_str;
	ch.server_name.e = ch.server_name.p + c->server_name.len;
	ch.ciphers = c->ciphers;
	ch.groups = c->groups;
	ch.algorithms = c->algorithms;

	c->rand.vtable->generate(&c->rand.vtable, c->client_random, sizeof(c->client_random));
	ch.random = c->client_random;

	// generate a public/private key for the high priority groups
	const br_ec_impl *ec = br_ec_get_default();
	uint8_t pub_keys[QUIC_MAX_KEYSHARE][BR_EC_KBUF_PUB_MAX_SIZE];
	c->key_num = (c->ciphers.e - c->ciphers.p) / 2;
	if (c->key_num > QUIC_MAX_KEYSHARE) {
		c->key_num = QUIC_MAX_KEYSHARE;
	}
	ch.key_num = c->key_num;
	for (size_t i = 0; i < ch.key_num; i++) {
		br_ec_keygen(&c->rand.vtable, ec, &c->priv_key[i], c->priv_key_data[i], big_16(ch.groups.p + (i * 2)));
		br_ec_compute_pub(ec, &ch.keys[i], pub_keys[i], &c->priv_key[i]);
	}

	// encode the TLS record
	qslice_t tls = { tx->data + tx->len, tx->data + sizeof(pkts->tx_crypto_buf) };
	if (tls.p > tls.e || encode_client_hello(&tls, &ch)) {
		return -1;
	}
	size_t from = tx->len;
	size_t to = tls.p - tx->data;
	tx->len = to;

	// encode the UDP packet
	uint8_t buf[DEFAULT_PACKET_SIZE];
	qslice_t udp = { buf, buf + sizeof(buf) };
	qtx_packet_t *pkt = encode_long_packet(c, &udp, QC_INITIAL, tx, from, to, true);
	if (pkt == NULL || pkt->to != to) {
		return -1;
	}

	// send it
	int ret = -1;
	for (int i = 0; i < QUIC_MAX_ADDR; i++) {
		qconnection_addr_t *a = &c->peer_addrs[i];
		if (a->len && !c->send(c->user, buf, udp.p - buf, (struct sockaddr*)&a->ss, a->len, &pkt->sent)) {
			ret = 0;
		}
	}
	
	return ret;
}

static br_ec_private_key *find_private_key(qconnection_t *c, int curve) {
	for (size_t i = 0; i < c->key_num; i++) {
		if (c->priv_key[i].curve == curve) {
			return &c->priv_key[i];
		}
	}
	return NULL;
}

#define MAX_LABEL_SIZE sizeof("QUIC_CLIENT_HANDSHAKE_TRAFFIC_SECRET")
static void log_key(qconnection_t *c, const char *label, const uint8_t *secret, size_t len) {
	char line[MAX_LABEL_SIZE + 1 + 2 * QUIC_HELLO_RANDOM_SIZE + 2 * QUIC_MAX_HASH_SIZE + 2];
	char *p = line + snprintf(line, MAX_LABEL_SIZE + 1, "%s ", label);
	for (size_t i = 0; i < QUIC_HELLO_RANDOM_SIZE; i++) {
		p += sprintf(p, "%02x", c->client_random[i]);
	}
	p += sprintf(p, " ");
	for (size_t i = 0; i < len; i++) {
		p += sprintf(p, "%02x", secret[i]);
	}
	*(p++) = '\n';
	*p = '\0';
	c->log_key(c->user, line);
}

static int init_handshake(qconnection_t *c, uint16_t cipher, br_ec_public_key *pk) {
	c->cipher = cipher;

	br_ec_private_key *sk = find_private_key(c, pk->curve);
	if (!sk) {
		return -1;
	}

	// generate the handshake secrets
	qpacket_buffer_t *init = &c->pkts[QC_INITIAL];
	qpacket_buffer_t *pkts = &c->pkts[QC_HANDSHAKE];

	qslice_t rx_hello = { init->rx_crypto_buf, init->rx_crypto_buf + init->rx_crypto.offset };
	qslice_t tx_hello = { init->tx_crypto_buf, init->tx_crypto_buf + init->tx_crypto.len };
	qslice_t ch = rx_hello;
	qslice_t sh = tx_hello;
	qkeyset_t *client = &pkts->rkey;
	qkeyset_t *server = &pkts->tkey;
	if (c->is_client) {
		ch = tx_hello;
		sh = rx_hello;
		client = &pkts->tkey;
		server = &pkts->rkey;
	}

	if (generate_handshake_secrets(&c->crypto_hash, ch, sh, pk, sk, cipher, client, server, c->master_secret)) {
		return -1;
	}

	if (c->log_key) {
		log_key(c, "QUIC_CLIENT_HANDSHAKE_TRAFFIC_SECRET", client->secret, client->hash_len);
		log_key(c, "QUIC_SERVER_HANDSHAKE_TRAFFIC_SECRET", server->secret, server->hash_len);
	}

	return 0;
}

static br_ec_public_key *find_public_key(struct client_hello *ch, int curve) {
	for (size_t i = 0; i < ch->key_num; i++) {
		if (ch->keys[i].curve == curve) {
			return &ch->keys[i];
		}
	}
	return NULL;
}

static int process_client_hello(qconnection_t *c, struct client_hello *ch) {
	// setup the server hello
	uint8_t random[QUIC_HELLO_RANDOM_SIZE];
	c->rand.vtable->generate(&c->rand.vtable, random, sizeof(random));
	memcpy(c->client_random, ch->random, QUIC_HELLO_RANDOM_SIZE);

	struct server_hello sh;
	sh.random = random;
	sh.cipher = TLS_AES_128_GCM_SHA256;

	// find the client's key
	br_ec_public_key *client_pk = find_public_key(ch, BR_EC_curve25519);
	if (!client_pk) {
		return -1;
	}

	// generate the server key
	const br_ec_impl *ec = br_ec_get_default();
	if (!c->key_num) {
		c->key_num = 1;
		br_ec_keygen(&c->rand.vtable, ec, &c->priv_key[0], c->priv_key_data, BR_EC_curve25519);
	}
	uint8_t pub_key[BR_EC_KBUF_PUB_MAX_SIZE];
	br_ec_compute_pub(ec, &sh.key, pub_key, &c->priv_key[0]);

	// set the server hostname
	ca_set2(&c->server_name, (char*)ch->server_name.p, ch->server_name.e - ch->server_name.p);

	// encode the initial records (server hello)
	{
		qpacket_buffer_t *pkts = &c->pkts[QC_INITIAL];
		qtx_stream_t *tx = &pkts->tx_crypto;
		qslice_t s = { tx->data + tx->len, tx->data + sizeof(pkts->tx_crypto_buf) };
		if (encode_server_hello(&s, &sh)) {
			return -1;
		}
		uint64_t from = tx->offset + tx->len;
		uint64_t to = tx->offset + (s.p - tx->data);
		tx->len = s.p - tx->data;

		if (send_long_packets(c, QC_INITIAL, tx, from, to)) {
			return -1;
		}
	}

	if (init_handshake(c, sh.cipher, client_pk)) {
		return -1;
	}

	// encode the handshake records (encrypted extensions, certificate, cert verify, finished)
	{
		qpacket_buffer_t *pkts = &c->pkts[QC_HANDSHAKE];
		qtx_stream_t *tx = &pkts->tx_crypto;
		qslice_t s = { tx->data + tx->len, tx->data + sizeof(pkts->tx_crypto_buf) };

		// Certificate
		uint8_t *cert_begin = s.p;
		if (encode_certificates(&s, c->next_cert, c->user)) {
			return -1;
		}
		c->crypto_hash.vtable->update(&c->crypto_hash.vtable, cert_begin, s.p - cert_begin);

		// CertificateVerify
		uint8_t verify[QUIC_MAX_CERT_VERIFY_SIZE];
		size_t vlen = generate_cert_verify(c->is_client, &c->crypto_hash.vtable, verify);
		uint8_t sig[QUIC_MAX_SIG_SIZE];
		uint8_t *verify_begin = s.p;
		int slen = c->sign(c->user, RSA_PKCS1_SHA256, verify, vlen, sig);
		if (slen < 0 || encode_verify(&s, RSA_PKCS1_SHA256, sig, (size_t)slen)) {
			return -1;
		}
		c->crypto_hash.vtable->update(&c->crypto_hash.vtable, verify_begin, s.p - verify_begin);

		// Finished
		uint8_t fin[QUIC_MAX_HASH_SIZE];
		size_t flen = generate_finish_verify(&pkts->tkey, &c->crypto_hash.vtable, fin);
		uint8_t *finish_begin = s.p;
		if (encode_finished(&s, fin, flen)) {
			return -1;
		}
		c->crypto_hash.vtable->update(&c->crypto_hash.vtable, finish_begin, s.p - finish_begin);

		uint64_t from = tx->offset + tx->len;
		uint64_t to = tx->offset + (s.p - tx->data);
		tx->len = s.p - tx->data;

		if (send_long_packets(c, QC_HANDSHAKE, tx, from, to)) {
			return -1;
		}
	}

	return 0;
}

static int process_server_hello(qconnection_t *c, struct server_hello *sh) {
	// TODO verify the cipher
	return init_handshake(c, sh->cipher, &sh->key);
}

static int verify_certificate_chain(qconnection_t *c, const qcertificate_t *certs, size_t num) {
	return c->verify_chain(c->user, certs, num, &c->cert_key);
}

static int verify_signature(qconnection_t *c, uint16_t algo, qslice_t sig) {
	uint8_t verify[QUIC_MAX_CERT_VERIFY_SIZE];
	size_t vlen = generate_cert_verify(!c->is_client, &c->crypto_hash.vtable, verify);

	switch (algo) {
	case RSA_PKCS1_SHA256:
		return verify_rsa_pkcs1(&br_sha256_vtable, BR_HASH_OID_SHA256, &c->cert_key, sig, verify, vlen);
	default:
		return -1;
	}
}

static int verify_finished(qconnection_t *c, qslice_t verify) {
	qpacket_buffer_t *pkts = &c->pkts[QC_HANDSHAKE];
	uint8_t fin[QUIC_MAX_HASH_SIZE];
	size_t flen = generate_finish_verify(&pkts->rkey, &c->crypto_hash.vtable, fin);
	if (flen != (size_t)(verify.e - verify.p) || memcmp(fin, verify.p, flen)) {
		return -1;
	}

	qkeyset_t *client = &pkts->rkey;
	qkeyset_t *server = &pkts->tkey;
	if (c->is_client) {
		client = &pkts->tkey;
		server = &pkts->rkey;
	}
	generate_protected_secrets(&c->crypto_hash.vtable, c->master_secret, c->cipher, client, server);

	// send client finished
	if (c->is_client) {
		qtx_stream_t *tx = &pkts->tx_crypto;
		qslice_t s = { tx->data + tx->len, tx->data + sizeof(pkts->tx_crypto_buf) };

		// Finished
		flen = generate_finish_verify(&pkts->tkey, &c->crypto_hash.vtable, fin);
		uint8_t *finish_begin = s.p;
		if (encode_finished(&s, fin, flen)) {
			return -1;
		}
		c->crypto_hash.vtable->update(&c->crypto_hash.vtable, finish_begin, s.p - finish_begin);

		uint64_t from = tx->offset + tx->len;
		uint64_t to = tx->offset + (s.p - tx->data);
		tx->len = s.p - tx->data;

		if (send_long_packets(c, QC_HANDSHAKE, tx, from, to)) {
			return -1;
		}
	}

	return 0;
}

static bool next_tls_record(qpacket_buffer_t *b, uint8_t *ptype, qslice_t *data) {
	uint8_t *p = b->rx_crypto_buf + b->rx_crypto_consumed;
	uint8_t *e = b->rx_crypto_buf + b->rx_crypto.offset;
	if (p + 4 > e) {
		return false;
	}
	uint32_t tls_len = big_24(p + 1);
	if (p + 4 + tls_len > e) {
		return false;
	}
	b->rx_crypto_consumed += 4 + tls_len;
	*ptype = p[0];
	data->p = p + 4;
	data->e = data->p + tls_len;
	return true;
}

static int decode_crypto(qpacket_buffer_t *b, qslice_t *s) {
	int64_t off = decode_varint(s);
	int64_t len = decode_varint(s);
	if (len < 0 || (s->e - s->p) < len) {
		return -1;
	}
	uint8_t *data = s->p;
	s->p += len;
	return receive_data(&b->rx_crypto, (uint64_t)off, data, (size_t)len);
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

static int process_protected(qconnection_t *c, qslice_t s) {
	if (c->hs_state != QC_RUNNING) {
		return -1;
	}


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
			if (!decode_crypto(pkts, &s)) {
				uint8_t type;
				qslice_t data;
				while (next_tls_record(pkts, &type, &data)) {
					switch (type) {
					case CLIENT_HELLO: {
						struct client_hello ch;
						if (c->hs_state != QC_WAIT_FOR_CLIENT_HELLO) {
							LOG(c->debug, "unexpected client hello message");
						} else if (decode_client_hello(data, &ch)) {
							LOG(c->debug, "client hello parse failure");
						} else {
							process_client_hello(c, &ch);
							c->hs_state = QC_WAIT_FOR_FINISHED;
						}
						break;
					}
					case SERVER_HELLO: {
						struct server_hello sh;
						if (c->hs_state != QC_WAIT_FOR_SERVER_HELLO) {
							LOG(c->debug, "unexpected server hello message");
						} else if (decode_server_hello(data, &sh)) {
							LOG(c->debug, "server hello parse failure");
						} else if (process_server_hello(c, &sh)) {
							LOG(c->debug, "server hello failure");
						} else {
							c->hs_state = QC_WAIT_FOR_CERTIFICATE;
						}
						break;
					}
					case CERTIFICATE: {
						size_t num;
						qcertificate_t certs[QUIC_MAX_CERTIFICATES];
						if (c->hs_state != QC_WAIT_FOR_CERTIFICATE) {
							LOG(c->debug, "unexpected certificate message");
						} else if (decode_certificates(data, certs, &num)) {
							LOG(c->debug, "certificate message parse failure");
						} else if (verify_certificate_chain(c, certs, num)) {
							LOG(c->debug, "certificate chain verification failure");
						} else {
							c->hs_state = QC_WAIT_FOR_VERIFY;
						}
						break;
					}
					case CERTIFICATE_VERIFY: {
						uint16_t algo;
						qslice_t sig;
						if (c->hs_state != QC_WAIT_FOR_VERIFY) {
							LOG(c->debug, "unexpected certificate verify message");
						} else if (decode_verify(data, &algo, &sig)) {
							LOG(c->debug, "verify parse failure");
						} else if (verify_signature(c, algo, sig)) {
							LOG(c->debug, "certificate verification failure");
						} else {
							c->hs_state = QC_WAIT_FOR_FINISHED;
						}
						break;
					}
					case FINISHED: {
						qslice_t verify;
						if (c->hs_state != QC_WAIT_FOR_FINISHED) {
							LOG(c->debug, "unexpected finished message");
						} else if (decode_finished(data, &verify)) {
							LOG(c->debug, "finished parse failure");
						} else if (verify_finished(c, verify)) {
							LOG(c->debug, "finished verification failure");
						} else {
							c->hs_state = QC_RUNNING;
						}
						break;
					}
					}
				}
			}
			break;
		}
	}
	return 0;
}

int qc_get_destination(void *buf, size_t len, uint8_t **p) {
	uint8_t *u = buf;
	if (!len) {
		return -1;
	}
	if (*u & LONG_HEADER_FLAG) {
		if (len < 6) {
			return -1;
		}
		if (big_32(u + 1) != QUIC_VERSION) {
			return -2;
		}
		uint8_t dcil = decode_id_len(u[5] >> 4);
		if (len < 6 + dcil) {
			return -1;
		}
		*p = u + 6;
		return dcil;

	} else {
		if (len < 1 + DEFAULT_SERVER_ID_LEN) {
			return -1;
		}
		*p = u + 1;
		return DEFAULT_SERVER_ID_LEN;
	}
}

int qc_on_recv(qconnection_t *c, void *buf, size_t len, const struct sockaddr *sa, size_t salen, tick_t rxtime) {
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
				// TODO send version negotiation
				// and handle version negotiation
				return -1;
			}
			uint8_t dcil = decode_id_len(s.p[0] >> 4);
			uint8_t scil = decode_id_len(s.p[0] & 0xF);
			s.p++;
			if (dcil != DEFAULT_SERVER_ID_LEN) {
				return -1;
			}

			if (!c->is_client && !c->local_id) {
				c->local_id = &c->local_ids[0];
				c->local_id->len = dcil;
				memcpy(c->local_id->id, s.p, dcil);
				s.p += dcil;
				c->peer_id = &c->peer_ids[0];
				c->peer_id->len = scil;
				memcpy(c->peer_id->id, s.p, scil);
				s.p += scil;

				qpacket_buffer_t *pkts = &c->pkts[QC_INITIAL];
				generate_initial_secrets(c->local_id, &pkts->rkey, &pkts->tkey);
			} else {
				s.p += dcil + scil;
			}

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
			if (pktnum < 0) {
				return -1;
			}

			receive_packet(pkts, pktnum);

			if (process_packet(c, data, level)) {
				return -1;
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
