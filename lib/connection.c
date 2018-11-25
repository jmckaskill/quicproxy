#include "connection.h"
#include "kdf.h"
#include <cutils/log.h>
#include <inttypes.h>


enum qhandshake_state {
	QC_RUNNING,
	QC_PROCESS_SERVER_HELLO,
	QC_PROCESS_EXTENSIONS,
	QC_PROCESS_CERTIFICATE,
	QC_PROCESS_VERIFY,
	QC_PROCESS_FINISHED,
};

static const char prng_nonce[] = "quicproxy prng nonce";

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

static void receive_packet(qconnection_t *c, enum qcrypto_level level, uint64_t pktnum);
static void send_data(qconnection_t *c, bool force_send);

static tickdiff_t crypto_timeout(qconnection_t *c, bool reset);
static int send_client_hello(qconnection_t *c, bool first_time, tick_t *psent);
static int send_server_hello(qconnection_t *c, const br_ec_public_key *pk, tick_t *psent);
static void on_handshake_timeout(apc_t *a, tick_t now);

static tickdiff_t retransmission_timeout(qconnection_t *c, bool reset);
static void on_retransmission_timeout(apc_t *a, tick_t now);

static tickdiff_t idle_timeout(qconnection_t *c);
static void on_idle_timeout(apc_t *a, tick_t now);
static void on_ping_timeout(apc_t *a, tick_t now);

static void on_ack_timeout(apc_t *a, tick_t now);

static int decode_stream(qconnection_t *c, uint8_t hdr, qslice_t *p);


//////////////////////////////
// Initialization

static int init_connection(qconnection_t *c, bool is_client, br_prng_seeder seedfn, qtx_packet_t *pktbuf, size_t num) {
	memset(c, 0, sizeof(*c));
	br_hmac_drbg_init(&c->rand, &br_sha256_vtable, prng_nonce, sizeof(prng_nonce));
	if (!seedfn) {
		seedfn = br_prng_seeder_system(NULL);
	}
	if (!seedfn || !seedfn(&c->rand.vtable)) {
		return -1;
	}

	c->is_client = is_client;

	if (is_client) {
		c->pkts[QC_INITIAL].sent_len = 10; // resend of client hellos
		c->pkts[QC_HANDSHAKE].sent_len = 5; // only have acks
	} else {
		// on the server side we limit the number of packets allowed to be in flight
		// this limits reflection attacks
		c->pkts[QC_INITIAL].sent_len = 2;
		c->pkts[QC_HANDSHAKE].sent_len = 3;
	}

	size_t hspkts = c->pkts[QC_INITIAL].sent_len + c->pkts[QC_HANDSHAKE].sent_len;
	if (hspkts >= num) {
		return -1;
	}
	c->pkts[QC_PROTECTED].sent_len = num - hspkts;
	c->pkts[QC_INITIAL].sent = pktbuf;
	c->pkts[QC_HANDSHAKE].sent = pktbuf + c->pkts[QC_INITIAL].sent_len;
	c->pkts[QC_PROTECTED].sent = pktbuf + hspkts;

	br_sha256_init(&c->msg_sha256);
	br_sha384_init(&c->msg_sha384);
	c->rtt = QUIC_DEFAULT_RTT;

	return 0;
}

static void generate_id(const br_prng_class **r, uint8_t *id) {
	id[0] = DEFAULT_SERVER_ID_LEN;
	(*r)->generate(r, id + 1, DEFAULT_SERVER_ID_LEN);
	memset(id + 1 + DEFAULT_SERVER_ID_LEN, 0, QUIC_ADDRESS_SIZE - DEFAULT_SERVER_ID_LEN - 1);
}

int qc_connect(qconnection_t *c, dispatcher_t *d, const qinterface_t **vt, const br_x509_class **x, const qconnect_params_t *p, qtx_packet_t *buf, size_t num) {
	if (init_connection(c, true, p->seeder, buf, num)) {
		return -1;
	}
	c->iface = vt;
	c->dispatcher = d;
	c->params = p;
	c->validator = x;
	generate_id(&c->rand.vtable, c->peer_id);
	generate_id(&c->rand.vtable, c->local_id);

	// generate a private key for the high priority groups
	const br_ec_impl *ec = br_ec_get_default();
	for (size_t i = 0, knum = MIN(QUIC_MAX_KEYSHARE, strlen(p->groups)); i < knum; i++) {
		if (!br_ec_keygen(&c->rand.vtable, ec, &c->keys[i], c->key_data[i], p->groups[i])) {
			return -1;
		}
	}

	tick_t now;
	if (send_client_hello(c, true, &now)) {
		return -1;
	}

	init_client_decoder(c);
	c->retransmit_count = 0;
	add_timed_apc(d, &c->retransmit_timer, now + crypto_timeout(c, true), &on_handshake_timeout);
	add_timed_apc(d, &c->idle_timer, now + idle_timeout(c), &on_idle_timeout);
	return 0;
}

int qc_accept(qconnection_t *c, dispatcher_t *d, const qinterface_t **vt, const qconnect_request_t *h, const qsigner_class *const *s, qtx_packet_t *buf, size_t num) {
	if (init_connection(c, false, h->server_params->seeder, buf, num)) {
		return -1;
	}
	c->iface = vt;
	c->dispatcher = d;
	c->params = h->server_params;
	c->signer = s;
	memcpy(c->peer_id, h->source, QUIC_ADDRESS_SIZE);
	memcpy(c->local_id, h->destination, QUIC_ADDRESS_SIZE);
	memcpy(c->client_random, h->client_random, QUIC_RANDOM_SIZE);

	// key group
	if (!h->key.curve || !br_ec_keygen(&c->rand.vtable, br_ec_get_default(), &c->keys[0], c->key_data[0], h->key.curve)) {
		return -1;
	}

	// certificates
	c->signature = choose_signature(c->signer, h->signatures);
	if (!c->signature) {
		return -1;
	}

	// cipher & transcript
	if (init_cipher(c, h->cipher) == NULL) {
		return -1;
	}
	(*c->msg_hash)->update(c->msg_hash, h->chello, h->chello_size);

	// transport parameters
	c->pending[PENDING_BIDI].max = h->client_params.bidi_streams;
	c->pending[PENDING_UNI].max = h->client_params.uni_streams;
	c->max_stream_data[STREAM_SERVER | STREAM_BIDI] = h->client_params.stream_data_bidi_remote;
	c->max_stream_data[STREAM_CLIENT | STREAM_BIDI] = h->client_params.stream_data_bidi_local;
	c->max_stream_data[STREAM_UNI] = h->client_params.stream_data_uni;
	c->max_data = h->client_params.max_data;

	// send server hello
	tick_t sent;
	receive_packet(c, QC_INITIAL, 0);
	if (send_server_hello(c, &h->key, &sent)) {
		return -1;
	}

	// initialize the protected keys
	uint8_t msg_hash[QUIC_MAX_HASH_SIZE];
	(*c->msg_hash)->out(c->msg_hash, msg_hash);
	init_protected_keys(c, msg_hash);

	init_server_decoder(c);
	add_timed_apc(d, &c->idle_timer, h->rxtime + idle_timeout(c), &on_idle_timeout);
	add_timed_apc(d, &c->retransmit_timer, sent + crypto_timeout(c, true), &on_handshake_timeout);
	return 0;
}

void qc_move(qconnection_t *c, dispatcher_t *d) {
	if (c->dispatcher != d) {
		move_apc(c->dispatcher, d, &c->idle_timer);
		move_apc(c->dispatcher, d, &c->retransmit_timer);
		c->dispatcher = d;
	}
}

void qc_close(qconnection_t *c) {
	cancel_apc(c->dispatcher, &c->idle_timer);
	cancel_apc(c->dispatcher, &c->retransmit_timer);
}



//////////////////////////
// Ack Generation

static void receive_packet(qconnection_t *c, enum qcrypto_level level, uint64_t pktnum) {
	qpacket_buffer_t *s = &c->pkts[level];
	if (level == QC_PROTECTED && !c->handshake_complete) {
		// Until this point, the client will send the finished message in every
		// protected packet. Once the server has acknowledged one, we know that it
		// got the finished frame and the handshake is complete.
		LOG(c->params->debug, "client handshake complete");
		c->handshake_complete = true;
	}
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
	while ((num_packets < 63) && (rx >> 63)) {
		first_block++;
		num_packets++;
		rx <<= 1;
	}
	*(s->p++) = first_block;

	while (rx != 0 && num_blocks < 16 && num_packets < 63) {
		// find the gap
		uint8_t gap = 0;
		while ((num_packets < 63) && !(rx >> 63)) {
			gap++;
			num_packets++;
			rx <<= 1;
		}

		// find the block
		uint8_t block = 0;
		while ((num_packets < 63) && (rx >> 63)) {
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


//////////////////////////////
// Sending crypto packets

struct long_packet {
	enum qcrypto_level level;
	const qcipher_class **key;
	size_t crypto_off;
	const uint8_t *crypto_data;
	size_t crypto_size;
	size_t padsz;
};

static size_t skip_crypto(struct long_packet *p, size_t sz) {
	size_t use = MIN(sz, p->crypto_size);
	p->crypto_off += use;
	p->crypto_data += use;
	p->crypto_size -= use;
	return sz - use;
}

static qtx_packet_t *encode_long_packet(qconnection_t *c, qslice_t *s, struct long_packet *p) {
	qpacket_buffer_t *pkts = &c->pkts[p->level];
	if (pkts->tx_next >= pkts->tx_oldest + pkts->sent_len) {
		// we've run out of room in the transmit packet buffer
		// need to wait for some packets to be ack'ed or lost
		return NULL;
	} else if (s->p + 1 + 4 + 2 * QUIC_ADDRESS_SIZE + 1 + 2 + 4 + QUIC_TAG_SIZE > s->e) {
		return NULL;
	} else if (s->p + p->padsz > s->e) {
		return NULL;
	}

	// header
	static const uint8_t headers[] = { INITIAL_PACKET,HANDSHAKE_PACKET,PROTECTED_PACKET };
	uint8_t *pkt_begin = s->p;
	*(s->p++) = headers[p->level];
	s->p = write_big_32(s->p, QUIC_VERSION);

	// connection IDs
	*(s->p++) = (encode_id_len(c->peer_id[0]) << 4) | encode_id_len(c->local_id[0]);
	s->p = append(s->p, c->peer_id + 1, c->peer_id[0]);
	s->p = append(s->p, c->local_id + 1, c->local_id[0]);

	// token
	if (p->level == QC_INITIAL) {
		*(s->p++) = 0;
	}

	// length
	s->p += 2;

	// packet number
	uint8_t *packet_number = s->p;
	s->p = encode_packet_number(s->p, pkts->tx_next);
	uint8_t *enc_begin = s->p;

	// ack frame
	if (pkts->rx_next && encode_ack_frame(c, s, pkts)) {
		return NULL;
	}

	// crypto frame
	uint64_t off = 0;
	size_t csz = 0;
	if (p->crypto_size) {
		size_t chdr = 1 + 4 + 4;
		if (s->p + chdr + QUIC_TAG_SIZE > s->e) {
			return NULL;
		}
		off = p->crypto_off;
		csz = MIN(p->crypto_size, (size_t)(s->e - s->p) - chdr);
		*(s->p++) = CRYPTO;
		s->p = encode_varint(s->p, p->crypto_off);
		s->p = encode_varint(s->p, csz);
		s->p = append(s->p, p->crypto_data, csz);
		skip_crypto(p, csz);
	}

	// padding
	size_t pkt_sz = (size_t)(s->p - pkt_begin) + QUIC_TAG_SIZE;
	if (pkt_sz < p->padsz) {
		size_t pad = p->padsz - pkt_sz;
		memset(s->p, PADDING, pad);
		s->p += pad;
	}

	// tag
	uint8_t *tag = s->p;
	s->p += QUIC_TAG_SIZE;

	// fill out length
	write_big_16(packet_number - 2, VARINT_16 | (uint16_t)(s->p - packet_number));

	(*p->key)->encrypt(p->key, pkts->tx_next, pkt_begin, enc_begin, tag);
	(*p->key)->protect(p->key, packet_number, (size_t)(enc_begin - packet_number), (size_t)(s->p - packet_number));

	qtx_packet_t *pkt = &pkts->sent[(pkts->tx_next++) % pkts->sent_len];
	pkt->off = off;
	pkt->len = csz;
	pkt->stream = NULL;
	return pkt;
}



///////////////////////////////////
// Timeouts

static tickdiff_t idle_timeout(qconnection_t *c) {
	return c->params->idle_timeout ? c->params->idle_timeout : QUIC_DEFAULT_IDLE_TIMEOUT;
}

static tickdiff_t crypto_timeout(qconnection_t *c, bool reset) {
	c->retransmit_count = reset ? 0 : c->retransmit_count + 1;
	return (2 << c->retransmit_count) * c->rtt;
}

static void call_disconnect(qconnection_t *c, int error) {
	// disconnect may delete our memory, so need to make sure we are decoupled before calling it
	qc_close(c);
	(*c->iface)->disconnect(c->iface, error);
}

static void on_idle_timeout(apc_t *w, tick_t now) {
	qconnection_t *c = container_of(w, qconnection_t, idle_timer);
	LOG(c->params->debug, "idle timeout");
	call_disconnect(c, QC_ERR_IDLE_TIMEOUT);
}



/////////////////////////////
// Sending Client Hello

static int send_client_hello(qconnection_t *c, bool first_time, tick_t *psent) {
	if (first_time) {
		c->rand.vtable->generate(&c->rand.vtable, c->client_random, sizeof(c->client_random));
	}

	// encode the TLS record
	uint8_t tlsbuf[1024];
	qslice_t tls = { tlsbuf, tlsbuf + sizeof(tlsbuf) };
	if (encode_client_hello(c, &tls)) {
		return -1;
	}

	if (first_time) {
		br_sha256_update(&c->msg_sha256, tlsbuf, tls.p - tlsbuf);
		br_sha384_update(&c->msg_sha384, tlsbuf, tls.p - tlsbuf);
	}

	qcipher_aes_gcm key;
	init_initial_cipher(&key, true, c->peer_id);

	// encode the UDP packet
	uint8_t udpbuf[DEFAULT_PACKET_SIZE];
	qslice_t udp = { udpbuf, udpbuf + sizeof(udpbuf) };
	struct long_packet lp = {
		.level = QC_INITIAL,
		.key = &key.vtable,
		.padsz = DEFAULT_PACKET_SIZE,
		.crypto_off = 0,
		.crypto_data = tlsbuf,
		.crypto_size = (size_t)(tls.p - tlsbuf),
	};
	qtx_packet_t *pkt = encode_long_packet(c, &udp, &lp);
	if (pkt == NULL) {
		return -1;
	}

	// send it
	LOG(c->params->debug, "TX CLIENT HELLO");
	if ((*c->iface)->send(c->iface, NULL, udpbuf, (size_t)(udp.p - udpbuf), &pkt->sent)) {
		return -1;
	}

	*psent = pkt->sent;
	return 0;
}





//////////////////////////////////
// Sending Server Hello

static int send_server_hello(qconnection_t *c, const br_ec_public_key *pk, tick_t *psent) {
	bool first_time = pk != NULL;
	if (first_time) {
		c->rand.vtable->generate(&c->rand.vtable, c->server_random, sizeof(c->server_random));
	}

	// server hello
	uint8_t tlsbuf[3 * 1024];
	qslice_t s = { tlsbuf, tlsbuf + sizeof(tlsbuf) };
	if (encode_server_hello(c, &s)) {
		return -1;
	}
	size_t init_len = (size_t)(s.p - tlsbuf);

	if (first_time) {
		uint8_t msg_hash[QUIC_MAX_HASH_SIZE];
		(*c->msg_hash)->update(c->msg_hash, tlsbuf, init_len);
		(*c->msg_hash)->out(c->msg_hash, msg_hash);

		// now that we have both the hellos in the msg hash, we can generate the handshake keys
		if (calc_handshake_secret(c->hs_secret, *c->msg_hash, msg_hash, pk, &c->keys[0])) {
			return -1;
		}

		derive_secret(c->hs_tx, *c->msg_hash, c->hs_secret, HANDSHAKE_SERVER, msg_hash);
		derive_secret(c->hs_rx, *c->msg_hash, c->hs_secret, HANDSHAKE_CLIENT, msg_hash);
		log_handshake(c->params->keylog, *c->msg_hash, c->hs_rx, c->hs_tx, c->client_random);
	}

	// EncryptedExtensions
	uint8_t *ext_begin = s.p;
	if (encode_encrypted_extensions(c, &s)) {
		return -1;
	}
	if (first_time) {
		(*c->msg_hash)->update(c->msg_hash, ext_begin, s.p - ext_begin);
	}

	// Certificate
	uint8_t *cert_begin = s.p;
	if (encode_certificates(&s, c->signer)) {
		return -1;
	}
	if (first_time) {
		(*c->msg_hash)->update(c->msg_hash, cert_begin, s.p - cert_begin);
		(*c->msg_hash)->out(c->msg_hash, c->cert_msg_hash);
	}

	// CertificateVerify
	uint8_t verify[QUIC_MAX_CERT_VERIFY_SIZE];
	size_t vlen = calc_cert_verify(verify, false, *c->msg_hash, c->cert_msg_hash);
	uint8_t sig[QUIC_MAX_SIG_SIZE];
	uint8_t *verify_begin = s.p;
	int slen = (*c->signer)->sign(c->signer, c->signature, verify, vlen, sig);
	if (slen < 0 || encode_verify(&s, c->signature, sig, (size_t)slen)) {
		return -1;
	}

	// Finished
	if (first_time) {
		uint8_t msg_hash[QUIC_MAX_HASH_SIZE];
		(*c->msg_hash)->update(c->msg_hash, verify_begin, s.p - verify_begin);
		(*c->msg_hash)->out(c->msg_hash, msg_hash);
		calc_finish_verify(c->finished_hash, *c->msg_hash, msg_hash, c->hs_tx);
	}
	uint8_t *finish_begin = s.p;
	if (encode_finished(&s, *c->msg_hash, c->finished_hash)) {
		return -1;
	}
	if (first_time) {
		(*c->msg_hash)->update(c->msg_hash, finish_begin, s.p - finish_begin);
	}

	qcipher_aes_gcm ik;
	qcipher_compat hk;
	init_initial_cipher(&ik, false, c->local_id);
	c->cipher->init(&hk.vtable, c->hs_tx);

	// encode and sent it
	struct long_packet ip = {
		.level = QC_INITIAL,
		.key = &ik.vtable,
		.crypto_off = 0,
		.crypto_data = tlsbuf,
		.crypto_size = init_len,
		.padsz = 0,
	};
	struct long_packet hp = {
		.level = QC_HANDSHAKE,
		.key = &hk.vtable,
		.crypto_off = 0,
		.crypto_data = ext_begin,
		.crypto_size = (size_t)(s.p - ext_begin),
		.padsz = 0,
	};

	LOG(c->params->debug, "TX SERVER HELLO");

	// try and combine both initial and handshake into the same udp packet and send them
	while (ip.crypto_size || hp.crypto_size) {
		uint8_t udpbuf[DEFAULT_PACKET_SIZE];
		qslice_t udp = { udpbuf, udpbuf + sizeof(udpbuf) };
		qtx_packet_t *pkts[2] = { NULL, NULL };
		if (ip.crypto_size) {
			pkts[0] = encode_long_packet(c, &udp, &ip);
		}
		if (hp.crypto_size) {
			pkts[1] = encode_long_packet(c, &udp, &hp);
		}
		if (!pkts[0] && !pkts[1]) {
			return -1;
		}
		if ((*c->iface)->send(c->iface, NULL, udpbuf, (size_t)(udp.p - udpbuf), psent)) {
			return -1;
		}
		if (pkts[0]) {
			pkts[0]->sent = *psent;
		}
		if (pkts[1]) {
			pkts[1]->sent = *psent;
		}
	}

	return 0;
}

static void on_handshake_timeout(apc_t *a, tick_t now) {
	qconnection_t *c = container_of(a, qconnection_t, retransmit_timer);
	// ignore the error if the send fails, we'll try again next timeout
	LOG(c->params->debug, "HS timeout %d", c->retransmit_count);
	if (c->is_client) {
		send_client_hello(c, false, &now);
	} else {
		send_server_hello(c, NULL, &now);
	}
	add_timed_apc(c->dispatcher, a, now + crypto_timeout(c, false), &on_handshake_timeout);
	LOG(c->params->debug, "");
}



////////////////////////////////////////////////
// ACK Processing

static void update_oldest_packet(qpacket_buffer_t *b) {
	do {
		b->tx_oldest++;
	} while (b->tx_oldest < b->tx_next && b->sent[b->tx_oldest % b->sent_len].off == UINT64_MAX);
}

// from & to form a closed range
static void process_ack_range(qconnection_t *c, enum qcrypto_level level, uint64_t from, uint64_t to) {
	qpacket_buffer_t *b = &c->pkts[level];
	for (uint64_t num = from;num <= to;num--) {
		if (num < b->tx_oldest) {
			continue;
		}

		qtx_packet_t *pkt = &b->sent[num % b->sent_len];
		qstream_t *s = pkt->stream;
		if (s) {
			rbnode *next_pkt = rb_next(&pkt->rb, RB_RIGHT);
			qtx_ack(s, pkt->off, pkt->len, next_pkt ? container_of(next_pkt, qtx_packet_t, rb)->off : s->tx.tail);
			rb_remove(&s->tx_packets, &pkt->rb);
			c->tx_stream_packets--;
		}
		pkt->off = UINT64_MAX;

		if (num == b->tx_oldest) {
			update_oldest_packet(b);
		}
	}
}

static void process_gap_range(qconnection_t *c, enum qcrypto_level level, uint64_t from, uint64_t to, uint64_t largest, tick_t lost) {
	qpacket_buffer_t *b = &c->pkts[level];
	for (uint64_t num = from;num <= to;num--) {
		if (num < b->tx_oldest) {
			continue;
		}
		qtx_packet_t *pkt = &b->sent[num % b->sent_len];
		if (level == QC_PROTECTED && num + 3 > largest && (int32_t)(pkt->sent - lost) > 0) {
			// the packet is too new to be lost yet by either the fast retransmit or early retransmit
			continue;
		}
		// packet is lost
		qstream_t *s = pkt->stream;
		if (s) {
			qtx_lost(s, pkt->off, pkt->len);
			rb_remove(&s->tx_packets, &pkt->rb);
			c->tx_stream_packets--;
		} else {
			add_apc(c->dispatcher, &c->retransmit_timer, &on_handshake_timeout);
		}
		pkt->off = UINT64_MAX;

		if (num == b->tx_oldest) {
			update_oldest_packet(b);
		}
	}
}

static int decode_ack(qconnection_t *c, enum qcrypto_level level, qslice_t *s, tick_t rxtime) {
	uint64_t largest, delay, count, first;
	if (decode_varint(s, &largest)
		|| decode_varint(s, &delay)
		|| decode_varint(s, &count)
		|| decode_varint(s, &first)
		|| first > largest) {
		return -1;
	}

	qpacket_buffer_t *b = &c->pkts[level];
	if (largest < b->tx_oldest) {
		return 0;
	} else if (largest >= b->tx_next) {
		return -1;
	}

	qtx_packet_t *pkt = &b->sent[largest % b->sent_len];
	int32_t diff = (int32_t)(rxtime - pkt->sent);
	if (diff < QUIC_MIN_RTT) {
		diff = QUIC_MIN_RTT;
	}
	c->rtt = (tick_t)diff;
	tick_t lost = rxtime - (diff * 9 / 8);

	uint64_t next = largest - first;
	process_ack_range(c, level, next, largest);

	while (count) {
		uint64_t gap, block;
		if (decode_varint(s, &gap) || decode_varint(s, &block) || gap + 2 + block > next) {
			return -1;
		}
		uint64_t to = next - gap - 2;
		uint64_t from = to - block;
		process_gap_range(c, level, to, next - 1, largest, lost);
		process_ack_range(c, level, from, to);
		next = from;
		count--;
	}

	if (b->tx_oldest < next) {
		process_gap_range(c, level, b->tx_oldest, next-1, largest, lost);
	}
	if (!c->tx_stream_packets && c->peer_verified) {
		// cancel the tail loss probe, we've got all our packets acknowledged
		if (c->params->ping_timeout) {
			add_timed_apc(c->dispatcher, &c->retransmit_timer, rxtime + c->params->ping_timeout, &on_ping_timeout);
		} else {
			cancel_apc(c->dispatcher, &c->retransmit_timer);
		}
	}

	return 0;
}


///////////////////////////
// Packet receiving

static uint8_t *find_non_padding(uint8_t *p, uint8_t *e) {
	while (p < e && *p == PADDING) {
		p++;
	}
	return p;
}

static void enable_ack_timer(qconnection_t *c, tick_t timeout) {
	if (!is_apc_active(&c->ack_timer) || (tickdiff_t)(timeout - c->ack_timer.wakeup) < 0) {
		add_timed_apc(c->dispatcher, &c->ack_timer, timeout, &on_ack_timeout);
	}
}

static int process_packet(qconnection_t *c, qslice_t s, enum qcrypto_level level, tick_t rxtime) {
	int err = 0;
	while (!err && s.p < s.e) {
		uint8_t hdr = *(s.p++);
		if (level == QC_PROTECTED && (hdr & STREAM_MASK) == STREAM) {
			if (!c->peer_verified) {
				return QC_ERR_DROP;
			}
			err = decode_stream(c, hdr, &s);
			enable_ack_timer(c, rxtime + QUIC_LONG_ACK_TIMEOUT);
		} else {
			switch (hdr) {
			default:
				return QC_ERR_UNKNOWN_FRAME;
			case PADDING:
				s.p = find_non_padding(s.p, s.e);
				break;
			case ACK:
				LOG(c->params->debug, "RX ACK %d", level);
				err = decode_ack(c, level, &s, rxtime);
				break;
			case CRYPTO:
				LOG(c->params->debug, "RX CRYPTO %d", level);
				err = decode_crypto(c, level, &s);
				if (level == QC_PROTECTED) {
					enable_ack_timer(c, rxtime + QUIC_SHORT_ACK_TIMEOUT);
				}
				break;
			case PING:
				LOG(c->params->debug, "RX PING %d", level);
				if (c->peer_verified) {
					enable_ack_timer(c, rxtime + QUIC_SHORT_ACK_TIMEOUT);
				} else {
					add_apc(c->dispatcher, &c->retransmit_timer, &on_handshake_timeout);
				}
				break;
			}
		}
	}
	return err;
}

int qc_get_destination(void *buf, size_t len, uint8_t *out) {
	uint8_t *u = buf;
	if (!len) {
		return -1;
	}
	uint8_t *pid;
	if (*u & LONG_HEADER_FLAG) {
		if (len < 6) {
			return QC_PARSE_ERROR;
		} else if (big_32(u + 1) != QUIC_VERSION) {
			return QC_WRONG_VERSION;
		} else if (decode_id_len(u[5] >> 4) != DEFAULT_SERVER_ID_LEN) {
			return QC_STATELESS_RETRY;
		}
		pid = u + 6;
	} else {
		if (len < 1 + DEFAULT_SERVER_ID_LEN) {
			return QC_PARSE_ERROR;
		}
		pid = u + 1;
	}
	out[0] = DEFAULT_SERVER_ID_LEN;
	memcpy(out + 1, pid, DEFAULT_SERVER_ID_LEN);
	memset(out + 1 + DEFAULT_SERVER_ID_LEN, 0, QUIC_ADDRESS_SIZE - DEFAULT_SERVER_ID_LEN - 1);
	return 0;
}

static int decrypt_packet(const qcipher_class **k, uint8_t *pkt_begin, qslice_t *s, uint64_t *pktnum) {
	// copy the encoded packet number data out so that if it is less
	// than 4 bytes, we can copy it back after
	uint8_t tmp[4];
	memcpy(tmp, s->p, 4);
	(*k)->protect(k, s->p, 4, s->e - s->p);
	uint8_t *begin = s->p;
	if (decode_packet_number(s, pktnum)) {
		return -1;
	}
	memcpy(s->p, tmp + (s->p - begin), 4 - (s->p - begin));
	s->e -= QUIC_TAG_SIZE;
	return s->p > s->e || !(*k)->decrypt(k, *pktnum, pkt_begin, s->p, s->e);
}

int qc_decode_request(qconnect_request_t *h, void *buf, size_t buflen, tick_t rxtime, const qconnect_params_t *params) {
	memset(h, 0, sizeof(*h));
	qslice_t s;
	s.p = (uint8_t*)buf;
	s.e = s.p + buflen;
	if (s.p + 6 > s.e || *(s.p++) != INITIAL_PACKET) {
		return QC_PARSE_ERROR;
	}
	uint32_t version = big_32(s.p);
	s.p += 4;
	if (version != QUIC_VERSION) {
		return QC_WRONG_VERSION;
	}
	h->destination[0] = decode_id_len(*s.p >> 4);
	h->source[0] = decode_id_len(*s.p & 0xF);
	s.p++;
	if (h->destination[0] != DEFAULT_SERVER_ID_LEN) {
		return QC_STATELESS_RETRY;
	}

	// destination
	memcpy(h->destination + 1, s.p, DEFAULT_SERVER_ID_LEN);
	s.p += DEFAULT_SERVER_ID_LEN;

	// source
	memcpy(h->source + 1, s.p, h->source[0]);
	s.p += h->source[0];

	// token
	uint64_t toksz;
	if (decode_varint(&s, &toksz) || toksz) {
		return QC_STATELESS_RETRY;
	}

	// length
	uint64_t paysz;
	if (decode_varint(&s, &paysz) || paysz > (uint64_t)(s.e - s.p)) {
		return QC_PARSE_ERROR;
	}
	s.e = s.p + paysz;

	// decrypt
	qcipher_aes_gcm key;
	uint64_t pktnum;
	init_initial_cipher(&key, true, h->destination);
	if (decrypt_packet(&key.vtable, (uint8_t*)buf, &s, &pktnum)) {
		return QC_PARSE_ERROR;
	}

	bool have_hello = false;

	while (s.p < s.e) {
		switch (*(s.p++)) {
		default:
			return QC_PARSE_ERROR;
		case PADDING:
			s.p = find_non_padding(s.p, s.e);
			break;
		case CRYPTO: {
			uint64_t off, len;
			if (decode_varint(&s, &off) || decode_varint(&s, &len)) {
				return QC_PARSE_ERROR;
			}
			h->chello = s.p;
			if (decode_client_hello(&s, h, params)) {
				return QC_PARSE_ERROR;
			}
			h->chello_size = (size_t)len;
			have_hello = true;
			break;
		}
		}
	}

	h->rxtime = rxtime;
	h->server_params = params;
	return have_hello ? QC_NO_ERROR : QC_PARSE_ERROR;
}

void qc_recv(qconnection_t *c, const void *addr, void *buf, size_t len, tick_t rxtime) {
	qslice_t s;
	s.p = buf;
	s.e = s.p + len;

	// Be careful that we only return an error to the app after
	// we verify the tag. An error to the app causes the connection
	// to be dropped. We want to be sure it's actually from the remote
	// and that's its not a fake message.

	while (s.p < s.e) {
		uint8_t *pkt_begin = s.p;
		uint8_t hdr = *(s.p++);
		if (hdr & LONG_HEADER_FLAG) {
			if (s.e - s.p < 5) {
				return;
			}
			uint32_t version = big_32(s.p);
			s.p += 4;
			if (version != QUIC_VERSION) {
				return;
			}
			// skip over ids
			uint8_t dcil = decode_id_len(*s.p >> 4);
			uint8_t scil = decode_id_len(*s.p & 0xF);
			s.p++;
			s.p += dcil + scil;

			enum qcrypto_level level = QC_INITIAL;
			qcipher_compat key;
			key.vtable = NULL;

			switch (hdr) {
			case INITIAL_PACKET: {
				level = QC_INITIAL;
				uint64_t toksz;
				if (decode_varint(&s, &toksz) || toksz > (uint64_t)(s.e - s.p)) {
					return;
				}
				s.p += (size_t)toksz;
				init_initial_cipher(&key.aes_gcm, !c->is_client, c->is_client ? c->peer_id : c->local_id);
				break;
			}
			case HANDSHAKE_PACKET:
				level = QC_HANDSHAKE;
				if (c->cipher) {
					c->cipher->init(&key.vtable, c->hs_rx);
				}
				break;
			default:
				break;
			}

			uint64_t paysz;
			if (decode_varint(&s, &paysz) || paysz > (uint64_t)(s.e - s.p)) {
				return;
			}
			qslice_t pkt = { s.p, s.p + (size_t) paysz };
			s.p = pkt.e;
			if (!key.vtable) {
				continue;
			}

			uint64_t pktnum;
			if (decrypt_packet(&key.vtable, pkt_begin, &pkt, &pktnum)) {
				continue;
			}
			add_timed_apc(c->dispatcher, &c->idle_timer, rxtime + idle_timeout(c), &on_idle_timeout);
			int err = process_packet(c, pkt, level, rxtime);
			if (err == QC_ERR_DROP) {
				continue;
			} else if (err) {
				call_disconnect(c, err);
				return;
			}
			receive_packet(c, level, pktnum);
			send_data(c, false);

		} else if ((hdr & SHORT_PACKET_MASK) == SHORT_PACKET) {
			// short header
			s.p += DEFAULT_SERVER_ID_LEN;
			if (s.p > s.e || !c->have_prot_keys) {
				return;
			}
			uint64_t pktnum;
			if (decrypt_packet(&c->prot_rx.vtable, pkt_begin, &s, &pktnum)) {
				return;
			}
			add_timed_apc(c->dispatcher, &c->idle_timer, rxtime + idle_timeout(c), &on_idle_timeout);
			int err = process_packet(c, s, QC_PROTECTED, rxtime);
			if (!err) {
				receive_packet(c, QC_PROTECTED, pktnum);
				send_data(c, false);
			} else if (err != QC_ERR_DROP) {
				call_disconnect(c, err);
			}
			return;
		}
	}
}



///////////////////////
// Stream management

static void insert_local_stream(qconnection_t *c, qstream_t *s, int uni) {
	int type = (uni ? STREAM_UNI : 0) | (c->is_client ? 0 : STREAM_SERVER);
	s->id = (c->pending[uni].next++ << 2) | type;
	s->tx_max = c->max_stream_data[type];
	rb_insert(&c->rx_streams[type], rb_begin(&c->rx_streams[type], RB_RIGHT), &s->rxnode, RB_RIGHT);
	rb_insert(&c->tx_streams, rb_begin(&c->tx_streams, RB_RIGHT), &s->txnode, RB_RIGHT);
	s->flags |= QSTREAM_IN_TX_QUEUE;
}

void qc_flush_stream(qconnection_t *c, qstream_t *s) {
	if (!(s->flags & QSTREAM_IN_TX_QUEUE) && qtx_can_send(s)) {
		rb_insert(&c->tx_streams, rb_begin(&c->tx_streams, RB_RIGHT), &s->txnode, RB_RIGHT);
		s->flags |= QSTREAM_IN_TX_QUEUE;
	}
}

static void insert_remote_stream(qconnection_t *c, qstream_t *s, int64_t id, rbnode *parent, rbdirection dir) {
	int type = (int)(id & 3);
	s->id = id;
	s->tx_max = c->max_stream_data[type];
	rb_insert(&c->rx_streams[type], parent, &s->rxnode, dir);
	if ((type & STREAM_UNI_MASK) == STREAM_BIDI) {
		qc_flush_stream(c, s);
	}
}

void qc_add_stream(qconnection_t *c, qstream_t *s) {
	int uni = s->rx.size ? 0 : 1;
	rb_insert(&c->pending[uni].streams, rb_begin(&c->pending[uni].streams, RB_RIGHT), &s->txnode, RB_RIGHT);
}




/////////////////////////
// Stream sending

static void insert_stream_packet(qstream_t *s, qtx_packet_t *pkt) {
	rbnode *p = s->tx_packets.root;
	rbdirection dir = RB_LEFT;
	while (p) {
		qtx_packet_t *pp = container_of(p, qtx_packet_t, rb);
		dir = (pp->off < pkt->off) ? RB_LEFT : RB_RIGHT;
		if (!rb_child(p, dir)) {
			break;
		}
		p = rb_child(p, dir);
	}
	rb_insert(&s->tx_packets, p, &pkt->rb, dir);
}

static void send_stream(qconnection_t *c, qstream_t *s, bool send_ping) {
	qpacket_buffer_t *pkts = &c->pkts[QC_PROTECTED];

	uint64_t off = 0;
	if (s) {
		off = s->tx.head;
		qbuf_next_valid(&s->tx, &off);
	}

	for (;;) {
		uint8_t buf[DEFAULT_PACKET_SIZE];
		qslice_t p = { buf, buf + sizeof(buf) };
		qtx_packet_t *init = NULL;
		qtx_packet_t *hs = NULL;

		if (!c->handshake_complete) {
			// get the ack for QC_INITIAL & QC_HANDSHAKE
			qcipher_aes_gcm ik;
			qcipher_compat hk;
			struct long_packet ip = { .level = QC_INITIAL,.key = &ik.vtable };
			struct long_packet hp = { .level = QC_HANDSHAKE,.key = &hk.vtable };
			init_initial_cipher(&ik, true, c->peer_id);
			c->cipher->init(&hk.vtable, c->hs_tx);
			init = encode_long_packet(c, &p, &ip);
			hs = encode_long_packet(c, &p, &hp);
			if (!init || !hs) {
				return;
			}
		}

		// Header
		uint8_t *pkt_begin = p.p;
		*(p.p++) = SHORT_PACKET;

		// destination
		p.p = append(p.p, c->peer_id + 1, c->peer_id[0]);

		// packet number
		uint8_t *packet_number = p.p;
		p.p = encode_packet_number(p.p, pkts->tx_next);
		uint8_t *enc_begin = p.p;

		// ack
		if (pkts->rx_next && encode_ack_frame(c, &p, pkts)) {
			return;
		}

		// client finished
		if (!c->handshake_complete) {
			*(p.p++) = CRYPTO;
			*(p.p++) = 0; // offset
			p.p += 2; // length
			uint8_t *fin_start = p.p;
			if (encode_finished(&p, c->cipher->hash, c->finished_hash)) {
				return;
			}
			write_big_16(fin_start - 2, VARINT_16 | (uint16_t)(p.p - fin_start));
		}

		// data
		size_t len = 0;
		if (s) {
			uint8_t *stream_header = p.p;
			*(p.p++) = STREAM;
			p.p = encode_varint(p.p, s->id);
			if (off > 0) {
				*stream_header |= STREAM_OFF_FLAG;
				p.p = encode_varint(p.p, off);
			}

			uint8_t *stream_len = NULL;
			if (!c->handshake_complete) {
				// specify a length so we can pad the frame out
				p.p += 2;
				stream_len = p.p;
				*stream_header |= STREAM_LEN_FLAG;
			}

			len = qbuf_copy(&s->tx, off, p.p, (size_t)(p.e - p.p) - QUIC_TAG_SIZE);
			p.p += len;
			off += len;

			if (stream_len) {
				write_big_16(stream_len - 2, VARINT_16 | (uint16_t)(len));
			}

			// set stream fin flag
			if (off == s->tx.tail && (s->flags & QSTREAM_END)) {
				*stream_header |= STREAM_FIN_FLAG;
			}

			LOG(c->params->debug, "TX STREAM %"PRIu64", off %"PRIu64", len %d, cfin %d", s->id, off, (int)len, (int)!c->handshake_complete);
		} else if (send_ping) {
			// this is a forced packet
			// add a ping to force the other side to respond
			*(p.p++) = PING;
			LOG(c->params->debug, "TX PING");
		} else {
			LOG(c->params->debug, "TX ACK");
		}

		// padding
		if (!c->handshake_complete) {
			size_t pad = (size_t)(p.e - p.p) - QUIC_TAG_SIZE;
			memset(p.p, PADDING, pad);
			p.p += pad;
		}

		// tag
		uint8_t *tag = p.p;
		p.p += QUIC_TAG_SIZE;

		const qcipher_class **k = &c->prot_tx.vtable;
		(*k)->encrypt(k, pkts->tx_next, pkt_begin, enc_begin, tag);
		(*k)->protect(k, packet_number, (size_t)(enc_begin - packet_number), (size_t)(p.p - packet_number));


		qtx_packet_t *pkt = &pkts->sent[pkts->tx_next % pkts->sent_len];
		if ((*c->iface)->send(c->iface, NULL, buf, (size_t)(p.p - buf), &pkt->sent)) {
			return;
		}
		if (init) {
			init->sent = pkt->sent;
		}
		if (hs) {
			hs->sent = pkt->sent;
		}
		pkt->off = off - len;
		pkt->len = len;
		pkt->stream = s;
		if (s) {
			c->tx_stream_packets++;
			insert_stream_packet(s, pkt);
		}
		pkts->tx_next++;

		cancel_apc(c->dispatcher, &c->ack_timer);
		if (s) {
			add_timed_apc(c->dispatcher, &c->retransmit_timer, pkt->sent + retransmission_timeout(c, true), &on_retransmission_timeout);
		}

		if (!s) {
			return;
		} else if (!qbuf_next_valid(&s->tx, &off)) {
			rb_remove(&c->tx_streams, &s->txnode);
			s->flags &= ~QSTREAM_IN_TX_QUEUE;
			return;
		}
	}
}

static void send_data(qconnection_t *c, bool force_send) {
	if (!c->peer_verified) {
		return;
	}
	uint64_t pktnum = force_send ? c->pkts[QC_PROTECTED].tx_next : 0;

	for (rbnode *n = rb_begin(&c->tx_streams, RB_LEFT); n != NULL;) {
		qstream_t *s = container_of(n, qstream_t, txnode);
		n = rb_next(n, RB_RIGHT);
		send_stream(c, s, false);
	}

	for (int uni = 0; uni <= 1; uni++) {
		for (rbnode *n = rb_begin(&c->pending[uni].streams, RB_LEFT); n != NULL;) {
			qstream_t *s = container_of(n, qstream_t, txnode);
			n = rb_next(n, RB_RIGHT);
			rb_remove(&c->pending[uni].streams, &s->txnode);
			insert_local_stream(c, s, uni);
			send_stream(c, s, false);
		}
	}

	if (c->pkts[QC_PROTECTED].tx_next == pktnum) {
		// we need to send something to get the client finished through
		// for the client, we need a packet for the finished data
		// for the server, we need a packet to return the ack
		// this also stops the crypto timeouts as it replaces it with the tail loss probe
		// this is also used for forcing a packet through for tail loss probe and RTO
		send_stream(c, NULL, force_send);
	}
}

static tickdiff_t retransmission_timeout(qconnection_t *c, bool reset) {
	if (reset) {
		c->retransmit_count = 0;
	}
	if (c->retransmit_count < 2) {
		// tail loss probe
		return MAX(((3 << (c->retransmit_count++)) * c->rtt) / 2, QUIC_MIN_TLP_TIMEOUT);
	} else {
		// full retransmission timeout
		int shift = c->retransmit_count++ - 2;
		return MAX(c->rtt << shift, QUIC_MIN_RTO_TIMEOUT);
	}
}

static void on_retransmission_timeout(apc_t *a, tick_t now) {
	qconnection_t *c = container_of(a, qconnection_t, retransmit_timer);
	LOG(c->params->debug, "RTO %d", c->retransmit_count);
	send_data(c, true);
	add_timed_apc(c->dispatcher, a, now + retransmission_timeout(c, false), &on_retransmission_timeout);
	LOG(c->params->debug, "");
}

static void on_ack_timeout(apc_t *a, tick_t now) {
	qconnection_t *c = container_of(a, qconnection_t, ack_timer);
	LOG(c->params->debug, "ACK timeout");
	send_stream(c, NULL, false);
	LOG(c->params->debug, "");
}

static void on_ping_timeout(apc_t *a, tick_t now) {
	qconnection_t *c = container_of(a, qconnection_t, retransmit_timer);
	LOG(c->params->debug, "PING timeout");
	send_data(c, true);
	add_timed_apc(c->dispatcher, a, now + c->params->ping_timeout, &on_ping_timeout);
	LOG(c->params->debug, "");
}





////////////////////////
// Stream receiving

static qstream_t *find_rx_stream(qconnection_t *c, uint64_t id, rbnode **parent, rbdirection *pdir) {
	rbnode *n = c->rx_streams[id & 3].root;
	*parent = NULL;
	*pdir = RB_LEFT;
	while (n) {
		qstream_t *s = container_of(n, qstream_t, rxnode);
		if (s->id == id) {
			return s;
		}
		*parent = n;
		*pdir = (id < s->id) ? RB_LEFT : RB_RIGHT;
		n = n->child[*pdir];
	}
	return NULL;
}

static int decode_stream(qconnection_t *c, uint8_t hdr, qslice_t *p) {
	uint64_t id;
	uint64_t off = 0;
	if (decode_varint(p, &id) || ((hdr & STREAM_OFF_FLAG) && decode_varint(p, &off))) {
		return -1;
	}
	uint64_t len = (uint64_t)(p->e - p->p);
	if ((hdr & STREAM_LEN_FLAG) && (decode_varint(p, &len) || len > (uint64_t)(p->e - p->p))) {
		return -1;
	}
	if (off + len >= STREAM_MAX) {
		return -1;
	}
	bool fin = (hdr & STREAM_FIN_FLAG) != 0;
	void *data = p->p;
	p->p += (size_t)len;
	rbnode *parent;
	rbdirection insert_dir;
	qstream_t *s = find_rx_stream(c, id, &parent, &insert_dir);
	if (!s) {
		if ((id & STREAM_SERVER) == (c->is_client ? 0 : STREAM_SERVER)) {
			// message on one of our streams, we'll ignore the data
			// TODO - send reset
			return 0;
		}
		s = (*c->iface)->open ? (*c->iface)->open(c->iface, (id & STREAM_UNI) != 0) : NULL;
		if (!s) {
			// TODO - send reset
			return 0;
		}
		insert_remote_stream(c, s, id, parent, insert_dir);
	}
	ssize_t have = qrx_received(s, fin, off, data, (size_t)len);
	if (have < 0) {
		// flow control error
		// TODO better error reporting
		return -1;
	}
	if (have > 0) {
		// we have new data
		if ((*c->iface)->read) {
			(*c->iface)->read(c->iface, s);
		}
		qrx_fold(s);
	}
	return 0;
}








