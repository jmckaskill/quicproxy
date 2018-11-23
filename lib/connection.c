#include "connection.h"
#include "kdf.h"
#include <cutils/log.h>


enum qhandshake_state {
	QC_RUNNING,
	QC_PROCESS_SERVER_HELLO,
	QC_PROCESS_EXTENSIONS,
	QC_PROCESS_CERTIFICATE,
	QC_PROCESS_VERIFY,
	QC_PROCESS_FINISHED,
};

static const char prng_nonce[] = "quic-proxy prng nonce";

#define MIN(a, b) ((a) < (b) ? (a) : (b))

static void send_data(qconnection_t *c);

int qc_init(qconnection_t *c, const qinterface_t **iface, br_prng_seeder seedfn, void *pktbuf, size_t bufsz) {
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

	br_sha256_init(&c->msg_sha256);
	br_sha384_init(&c->msg_sha384);
	c->iface = iface;
	c->rtt = QUIC_DEFAULT_RTT;

	return 0;
}

static void generate_ids(qconnection_t *c) {
	c->rand.vtable->generate(&c->rand.vtable, &c->local_id, sizeof(c->local_id));
	c->peer_id[0] = DEFAULT_SERVER_ID_LEN;
	c->rand.vtable->generate(&c->rand.vtable, c->peer_id+1, DEFAULT_SERVER_ID_LEN);
	memset(&c->peer_id + 1 + DEFAULT_SERVER_ID_LEN, 0, sizeof(c->peer_id) - 1 - DEFAULT_SERVER_ID_LEN);
}

static void receive_packet(qconnection_t *c, enum qcrypto_level level, uint64_t pktnum) {
	qpacket_buffer_t *s = &c->pkts[level];
	if (level == QC_PROTECTED) {
		c->handshake_acknowledged = true;
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
	qpacket_buffer_t *pkts = &c->pkts[level];
	if (pkts->tx_next >= pkts->tx_oldest + pkts->sent_len) {
		// we've run out of room in the transmit packet buffer
		// need to wait for some packets to be ack'ed or lost
		return -1;
	}
	size_t hsz = 1;
	hsz += 4; // version
	hsz += 1 + c->peer_id[0] + DEFAULT_SERVER_ID_LEN;
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
		data->p += pad;
	}

	// header
	*(s->p++) = headers[level];
	s->p = write_big_32(s->p, QUIC_VERSION);

	// connection IDs
	*(s->p++) = (encode_id_len(c->peer_id[0]) << 4) | encode_id_len(DEFAULT_SERVER_ID_LEN);
	s->p = append(s->p, c->peer_id + 1, c->peer_id[0]);
	s->p = write_little_64(s->p, c->local_id);

	// token
	if (level == QC_INITIAL) {
		*(s->p++) = 0;
	}

	// length
	size_t data_sz = (size_t)(data->p + QUIC_TAG_SIZE - s->p - 2);
	s->p = write_big_16(s->p, VARINT_16 | (uint16_t)data_sz);

	// packet number
	uint8_t *packet_number = s->p;
	s->p = encode_packet_number(s->p, pkts->tx_next);
	uint8_t *enc_begin = s->p;

	// tag
	uint8_t *tag = data->p;
	s->p = data->p + QUIC_TAG_SIZE;

	const qcipher_class **cipher = &pkts->tkey.u.vtable;
	(*cipher)->encrypt(cipher, pkts->tx_next, pkts->tkey.data_iv, pkt_begin, enc_begin, tag);
	(*cipher)->protect(cipher, packet_number, (size_t)(enc_begin - packet_number), data_sz);

	return &pkts->sent[(pkts->tx_next++) % pkts->sent_len];
}

static qtx_packet_t *encode_crypto_packet(qconnection_t *c, qslice_t *s, enum qcrypto_level level, size_t off, const void *data, size_t sz, size_t minsz) {
	qslice_t p;
	if (start_long_packet(c, level, *s, &p)) {
		return NULL;
	}
	qpacket_buffer_t *pkts = &c->pkts[level];
	if (pkts->rx_next && encode_ack_frame(c, &p, pkts)) {
		return NULL;
	}

	if (sz) {
		size_t chdr = 1 + 4 + 4;
		if (p.p + chdr > p.e) {
			return NULL;
		}
		sz = MIN(sz, (size_t)(p.e - p.p) - chdr);
		*(p.p++) = CRYPTO;
		p.p = encode_varint(p.p, off);
		p.p = encode_varint(p.p, sz);
		p.p = append(p.p, data, sz);
	}

	qtx_packet_t *pkt = finish_long_packet(c, level, s, &p, minsz);
	pkt->stream = NULL;
	pkt->off = off;
	pkt->len = sz;
	return pkt;
}


static void calculate_timeout(qconnection_t *c, qmicrosecs_t *ptimeout) {
	*ptimeout = timer_min(c->idle_timer, c->retransmit_timer);
}

int qc_connect(qconnection_t *c, const char *server_name, const br_x509_class **validator, const qconnect_params_t *params, qmicrosecs_t *ptimeout) {
	c->params = params;
	c->server_name = server_name;
	c->validator = validator;
	c->is_client = true;
	c->rand.vtable->generate(&c->rand.vtable, c->client_random, sizeof(c->client_random));
	generate_ids(c);

	qpacket_buffer_t *init = &c->pkts[QC_INITIAL];
	generate_initial_secrets(c->peer_id, &init->tkey, &init->rkey);

	// generate a private key for the high priority groups
	const br_ec_impl *ec = br_ec_get_default();
	c->key_num = strlen(params->groups);
	if (c->key_num > QUIC_MAX_KEYSHARE) {
		c->key_num = QUIC_MAX_KEYSHARE;
	}
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

	br_sha256_update(&c->msg_sha256, tlsbuf, tls.p - tlsbuf);
	br_sha384_update(&c->msg_sha384, tlsbuf, tls.p - tlsbuf);

	// encode the UDP packet
	uint8_t udpbuf[DEFAULT_PACKET_SIZE];
	qslice_t udp = { udpbuf, udpbuf + sizeof(udpbuf) };
	qtx_packet_t *pkt = encode_crypto_packet(c, &udp, QC_INITIAL, 0, tlsbuf, (size_t)(tls.p - tlsbuf), 1200);
	if (pkt == NULL) {
		return -1;
	}

	// send it
	if ((*c->iface)->send(c->iface, NULL, 0, udpbuf, (size_t)(udp.p - udpbuf), &pkt->sent)) {
		return -1;
	}

	init_client_decoder(c);
	c->idle_timer = pkt->sent + (params->idle_timeout ? params->idle_timeout : QUIC_DEFAULT_IDLE_TIMEOUT);
	c->retransmit_timer = pkt->sent + (2 * c->rtt);
	calculate_timeout(c, ptimeout);
	return 0;
}

static const qsignature_class *get_signature(const qsigner_class *const *signer, uint64_t client_mask) {
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

int qc_accept(qconnection_t *c, const qconnect_request_t *h, const qsigner_class *const *signer, qmicrosecs_t *ptimeout) {
	// general setup
	memcpy(c->peer_id, h->source, QUIC_ADDRESS_SIZE);
	c->local_id = h->destination;
	c->is_client = false;

	// nonces
	memcpy(c->client_random, h->random, QUIC_RANDOM_SIZE);
	c->rand.vtable->generate(&c->rand.vtable, c->server_random, QUIC_RANDOM_SIZE);

	uint8_t addr[9];
	addr[0] = DEFAULT_SERVER_ID_LEN;
	write_little_64(addr + 1, h->destination);
	qpacket_buffer_t *init = &c->pkts[QC_INITIAL];
	generate_initial_secrets(addr, &init->rkey, &init->tkey);
	receive_packet(c, QC_INITIAL, 0);

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
	c->params = h->server_params;

	// cipher & transcript
	const br_hash_class **msgs = init_cipher(c, h->cipher);
	(*msgs)->update(msgs, h->raw, h->raw_size);

	// transport parameters
	c->pending_streams[PENDING_BIDI].max = h->client_params.bidi_streams;
	c->pending_streams[PENDING_UNI].max = h->client_params.uni_streams;
	c->max_stream_data[STREAM_SERVER | STREAM_BIDI] = h->client_params.stream_data_bidi_remote;
	c->max_stream_data[STREAM_CLIENT | STREAM_BIDI] = h->client_params.stream_data_bidi_local;
	c->max_stream_data[STREAM_UNI] = h->client_params.stream_data_uni;
	c->max_data = h->client_params.max_data;

	// server hello
	uint8_t tlsbuf[3 * 1024];
	qslice_t s = { tlsbuf, tlsbuf + sizeof(tlsbuf) };
	if (encode_server_hello(c, &s)) {
		return -1;
	}
	size_t init_len = (size_t)(s.p - tlsbuf);

	uint8_t msg_hash[QUIC_MAX_HASH_SIZE];
	(*msgs)->update(msgs, tlsbuf, init_len);
	(*msgs)->out(msgs, msg_hash);

	// now that we have both the hellos in the msg hash, we can generate the handshake keys
	qpacket_buffer_t *hs = &c->pkts[QC_HANDSHAKE];
	if (generate_handshake_secrets(c->cipher, msg_hash, &h->key, &c->keys[0], &hs->rkey, &hs->tkey, c->master_secret)) {
		return -1;
	}

	log_handshake(&hs->rkey, &hs->tkey, c->client_random, c->keylog);

	// EncryptedExtensions
	uint8_t *ext_begin = s.p;
	if (encode_encrypted_extensions(c, &s)) {
		return -1;
	}
	(*msgs)->update(msgs, ext_begin, s.p - ext_begin);

	// Certificate
	uint8_t *cert_begin = s.p;
	if (encode_certificates(&s, signer)) {
		return -1;
	}

	(*msgs)->update(msgs, cert_begin, s.p - cert_begin);
	(*msgs)->out(msgs, msg_hash);

	// CertificateVerify
	uint8_t verify[QUIC_MAX_CERT_VERIFY_SIZE];
	size_t vlen = generate_cert_verify(*msgs, c->is_client, msg_hash, verify);
	uint8_t sig[QUIC_MAX_SIG_SIZE];
	uint8_t *verify_begin = s.p;
	int slen = (*signer)->sign(signer, c->signature, verify, vlen, sig);
	if (slen < 0 || encode_verify(&s, c->signature, sig, (size_t)slen)) {
		return -1;
	}

	(*msgs)->update(msgs, verify_begin, s.p - verify_begin);
	(*msgs)->out(msgs, msg_hash);

	// Finished
	uint8_t fin[QUIC_MAX_HASH_SIZE];
	size_t flen = generate_finish_verify(&hs->tkey, msg_hash, fin);
	uint8_t *finish_begin = s.p;
	if (encode_finished(&s, fin, flen)) {
		return -1;
	}
	size_t hs_len = (size_t)(s.p - tlsbuf) - init_len;

	(*msgs)->update(msgs, finish_begin, s.p - finish_begin);
	(*msgs)->out(msgs, msg_hash);

	qpacket_buffer_t *prot = &c->pkts[QC_PROTECTED];
	generate_protected_secrets(c->cipher, msg_hash, c->master_secret, &prot->rkey, &prot->tkey);
	log_protected(&prot->rkey, &prot->tkey, c->client_random, c->keylog);

	// encode and sent it
	size_t init_sent = 0;
	size_t hs_sent = 0;
	while (init_sent < init_len || hs_sent < hs_len) {
		uint8_t udpbuf[DEFAULT_PACKET_SIZE];
		qslice_t udp = { udpbuf, udpbuf + sizeof(udpbuf) };
		qtx_packet_t *pkts[2] = { NULL, NULL };
		if (init_sent < init_len) {
			pkts[0] = encode_crypto_packet(c, &udp, QC_INITIAL, init_sent, tlsbuf + init_sent, init_len - init_sent, 0);
			if (pkts[0]) {
				init_sent += pkts[0]->len;
			}
		}
		if (hs_sent < hs_len) {
			pkts[1] = encode_crypto_packet(c, &udp, QC_HANDSHAKE, hs_sent, tlsbuf + init_len + hs_sent, hs_len - hs_sent, 0);
			if (pkts[1]) {
				hs_sent += pkts[1]->len;
			}
		}
		qmicrosecs_t txtime;
		if ((*c->iface)->send(c->iface, NULL, 0, udpbuf, (size_t)(udp.p - udpbuf), &txtime)) {
			return -1;
		}
		if (pkts[0]) {
			pkts[0]->sent = txtime;
		}
		if (pkts[1]) {
			pkts[1]->sent = txtime;
		}
	}

	init_server_decoder(c);
	c->idle_timer = h->rxtime + (h->server_params->idle_timeout ? h->server_params->idle_timeout : QUIC_DEFAULT_IDLE_TIMEOUT);
	c->retransmit_timer = c->idle_timer + 1;
	calculate_timeout(c, ptimeout);

	return 0;
}

static void update_oldest_packet(qpacket_buffer_t *b) {
	do {
		b->tx_oldest++;
	} while (b->tx_oldest < b->tx_next && b->sent[b->tx_oldest % b->sent_len].off == UINT64_MAX);
}

// from & to form a closed range
static void process_ack_range(qpacket_buffer_t *b, uint64_t from, uint64_t to) {
	for (int64_t idx = to;idx >= (int64_t)from;idx--) {
		uint64_t num = (uint64_t)idx;
		if (num < b->tx_oldest) {
			break;
		}

		qtx_packet_t *pkt = &b->sent[num % b->sent_len];
		qstream_t *s = pkt->stream;
		if (s) {
			rbnode *next_pkt = rb_next(&pkt->rb, RB_RIGHT);
			qtx_ack(s, pkt->off, pkt->len, next_pkt ? container_of(next_pkt, qtx_packet_t, rb)->off : s->tx.tail);
			rb_remove(&s->tx_packets, &pkt->rb);
		}
		pkt->off = UINT64_MAX;

		if (num == b->tx_oldest) {
			update_oldest_packet(b);
		}
	}
}

static void process_gap_range(qpacket_buffer_t *b, uint64_t from, uint64_t to, uint64_t largest, qmicrosecs_t lost) {
	for (int64_t idx = to; idx >= (int64_t)from; idx--) {
		uint64_t num = (uint64_t)idx;
		if (num < b->tx_oldest) {
			break;
		}
		qtx_packet_t *pkt = &b->sent[num % b->sent_len];
		if (num + 3 > largest && (int32_t)(pkt->sent - lost) > 0) {
			// the packet is too new to be lost yet by either the fast retransmit or early retransmit
			continue;
		}
		// packet is lost
		qstream_t *s = pkt->stream;
		if (s) {
			qtx_lost(s, pkt->off, pkt->len);
			rb_remove(&s->tx_packets, &pkt->rb);
		}
		pkt->off = UINT64_MAX;

		if (num == b->tx_oldest) {
			update_oldest_packet(b);
		}
	}
}

static int decode_ack(qconnection_t *c, qpacket_buffer_t *b, qslice_t *s, qmicrosecs_t rxtime) {
	uint64_t largest, delay, count, first;
	if (decode_varint(s, &largest)
		|| decode_varint(s, &delay)
		|| decode_varint(s, &count)
		|| decode_varint(s, &first)
		|| first > largest) {
		return -1;
	}

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
	c->rtt = (qmicrosecs_t)diff;
	qmicrosecs_t lost = rxtime - (diff * 9 / 8);

	uint64_t next = largest - first;
	process_ack_range(b, next, largest);

	while (count) {
		uint64_t gap, block;
		if (decode_varint(s, &gap) || decode_varint(s, &block) || gap + 2 + block > next) {
			return -1;
		}
		uint64_t to = next - gap - 2;
		uint64_t from = to - block;
		process_gap_range(b, to, next - 1, largest, lost);
		process_ack_range(b, from, to);
		next = from;
		count--;
	}

	if (b->tx_oldest < next) {
		process_gap_range(b, b->tx_oldest, next-1, largest, lost);
	}

	return 0;
}

static uint8_t *find_non_padding(uint8_t *p, uint8_t *e) {
	while (p < e && *p == PADDING) {
		p++;
	}
	return p;
}

static qstream_t *find_stream(qconnection_t *c, int64_t id, rbnode **parent, rbdirection *pdir) {
	rbnode *n = c->sorted_streams[id & 3].root;
	*parent = NULL;
	*pdir = RB_LEFT;
	while (n) {
		qstream_t *s = container_of(n, qstream_t, rb);
		if (s->id == id) {
			return s;
		}
		*parent = n;
		*pdir = (id < s->id) ? RB_LEFT : RB_RIGHT;
		n = n->child[*pdir];
	}
	return NULL;
}

static void insert_local_stream(qconnection_t *c, qstream_t *s, int uni) {
	int type = (uni ? STREAM_UNI : 0) | (c->is_client ? 0 : STREAM_SERVER);
	s->id = (c->pending_streams[uni].next++ << 2) | type;
	s->tx_max = c->max_stream_data[type];
	rb_insert(&c->sorted_streams[type], rb_begin(&c->sorted_streams[type], RB_RIGHT), &s->rb, RB_RIGHT);
	s->flags |= QSTREAM_TX_DIRTY;
	s->prev = NULL;
	s->next = c->tx_streams;
	c->tx_streams = s;
}

static void insert_remote_stream(qconnection_t *c, qstream_t *s, int64_t id, rbnode *parent, rbdirection dir) {
	int type = (int)(id & 3);
	s->id = id;
	s->tx_max = c->max_stream_data[type];
	rb_insert(&c->sorted_streams[type], parent, &s->rb, dir);
	if ((type & STREAM_UNI_MASK) == STREAM_BIDI) {
		s->prev = NULL;
		s->next = c->tx_streams;
		c->tx_streams = s;
	}
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
	qstream_t *s = find_stream(c, id, &parent, &insert_dir);
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

static int process_packet(qconnection_t *c, qslice_t s, enum qcrypto_level level, qmicrosecs_t rxtime) {
	qpacket_buffer_t *pkts = &c->pkts[level];
	int err = 0;
	while (!err && s.p < s.e) {
		uint8_t hdr = *(s.p++);
		if (level == QC_PROTECTED && (hdr & STREAM_MASK) == STREAM) {
			if (!c->handshake_complete) {
				return QC_ERR_DROP;
			}
			err = decode_stream(c, hdr, &s);
		} else {
			switch (hdr) {
			default:
				return QC_ERR_UNKNOWN_FRAME;
			case PADDING:
				s.p = find_non_padding(s.p, s.e);
				break;
			case ACK:
				err = decode_ack(c, pkts, &s, rxtime);
				break;
			case CRYPTO:
				err = decode_crypto(c, level, &s);
				break;
			}
		}
	}
	return err;
}

int qc_get_destination(void *buf, size_t len, uint64_t *out) {
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
	*out = little_64(pid);
	return 0;
}

static int decrypt_packet(qkeyset_t *keys, uint8_t *pkt_begin, qslice_t *s, uint64_t *pktnum) {
	// copy the encoded packet number data out so that if it is less
	// than 4 bytes, we can copy it back after
	uint8_t tmp[4];
	memcpy(tmp, s->p, 4);
	keys->u.vtable->protect(&keys->u.vtable, s->p, 4, s->e - s->p);
	uint8_t *begin = s->p;
	if (decode_packet_number(s, pktnum)) {
		return -1;
	}
	memcpy(s->p, tmp + (s->p - begin), 4 - (s->p - begin));
	s->e -= QUIC_TAG_SIZE;
	return s->p > s->e || !keys->u.vtable->decrypt(&keys->u.vtable, *pktnum, keys->data_iv, pkt_begin, s->p, s->e);
}

int qc_decode_request(qconnect_request_t *h, void *buf, size_t buflen, qmicrosecs_t rxtime, const qconnect_params_t *params) {
	memset(h, 0, sizeof(*h));
	qslice_t s;
	s.p = (uint8_t*)buf;
	s.e = s.p + buflen;
	if (s.p + 6 > s.e || *(s.p++) != INITIAL_PACKET) {
		return -1;
	}
	uint32_t version = big_32(s.p);
	s.p += 4;
	if (version != QUIC_VERSION) {
		return QC_WRONG_VERSION;
	}
	uint8_t dcil = decode_id_len(*s.p >> 4);
	uint8_t scil = decode_id_len(*s.p & 0xF);
	s.p++;
	if (dcil != DEFAULT_SERVER_ID_LEN) {
		return QC_STATELESS_RETRY;
	}

	// destination
	h->destination = little_64(s.p);
	s.p += DEFAULT_SERVER_ID_LEN;

	// source
	h->source[0] = scil;
	memcpy(h->source+1, s.p, scil);
	memset(h->source + 1 + scil, 0, sizeof(h->source) - 1 - scil);
	s.p += scil;

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
	qkeyset_t key;
	uint8_t addr[9];
	addr[0] = DEFAULT_SERVER_ID_LEN;
	write_little_64(addr + 1, h->destination);
	generate_initial_secrets(addr, &key, NULL);
	uint64_t pktnum;
	if (decrypt_packet(&key, (uint8_t*)buf, &s, &pktnum)) {
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
			h->raw = s.p;
			if (decode_client_hello(&s, h, params)) {
				return QC_PARSE_ERROR;
			}
			h->raw_size = (size_t)len;
			have_hello = true;
			break;
		}
		}
	}

	h->rxtime = rxtime;
	h->server_params = params;
	return have_hello ? 0 : QC_PARSE_ERROR;
}

int qc_recv(qconnection_t *c, const void *addr, size_t addrlen, void *buf, size_t len, qmicrosecs_t rxtime, qmicrosecs_t *ptimeout) {
	qslice_t s;
	s.p = buf;
	s.e = s.p + len;

	// Be careful that we only return an error to the app after
	// we verify the tag. An error to the app causes the connection
	// to be dropped. We want to be sure it's actually from the remote
	// and that's its not a replay.

	while (s.p < s.e) {
		uint8_t *pkt_begin = s.p;
		uint8_t hdr = *(s.p++);
		if (hdr & LONG_HEADER_FLAG) {
			if (s.e - s.p < 5) {
				goto end;
			}
			uint32_t version = big_32(s.p);
			s.p += 4;
			if (version != QUIC_VERSION) {
				goto end;
			}
			// skip over ids
			uint8_t dcil = decode_id_len(*s.p >> 4);
			uint8_t scil = decode_id_len(*s.p & 0xF);
			s.p++;
			s.p += dcil + scil;

			enum qcrypto_level level;

			switch (hdr) {
			case INITIAL_PACKET: {
				level = QC_INITIAL;
				uint64_t toksz;
				if (decode_varint(&s, &toksz) || toksz > (uint64_t)(s.e - s.p)) {
					goto end;
				}
				s.p += (size_t)toksz;
				break;
			}
			case HANDSHAKE_PACKET:
				level = QC_HANDSHAKE;
				break;
			case PROTECTED_PACKET:
				level = QC_PROTECTED;
				break;
			default:
				level = QC_UNKNOWN;
				break;
			}

			uint64_t paysz;
			if (decode_varint(&s, &paysz) || paysz > (uint64_t)(s.e - s.p)) {
				goto end;
			}
			qslice_t pkt = { s.p, s.p + (size_t) paysz };
			s.p = pkt.e;
			if (level == QC_UNKNOWN) {
				continue;
			}

			uint64_t pktnum;
			if (decrypt_packet(&c->pkts[level].rkey, pkt_begin, &pkt, &pktnum)) {
				continue;
			}
			int err = process_packet(c, pkt, level, rxtime);
			if (err == QC_ERR_DROP) {
				continue;
			} else if (err) {
				return err;
			}
			receive_packet(c, level, pktnum);
			send_data(c);

		} else if ((hdr & SHORT_PACKET_MASK) == SHORT_PACKET) {
			// short header
			s.p += DEFAULT_SERVER_ID_LEN;
			if (s.p > s.e) {
				goto end;
			}
			uint64_t pktnum;
			if (decrypt_packet(&c->pkts[QC_PROTECTED].rkey, pkt_begin, &s, &pktnum)) {
				goto end;
			}
			int err = process_packet(c, s, QC_PROTECTED, rxtime);
			if (err == QC_ERR_DROP) {
				goto end;
			} else if (err) {
				return err;
			} else {
				receive_packet(c, QC_PROTECTED, pktnum);
				send_data(c);
				goto end;
			}
		}
	}

end:
	calculate_timeout(c, ptimeout);
	return 0;
}

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

static void send_stream(qconnection_t *c, qstream_t *s) {
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

		if (!c->handshake_acknowledged) {
			// get the ack for QC_INITIAL & QC_HANDSHAKE
			init = encode_crypto_packet(c, &p, QC_INITIAL, 0, NULL, 0, 0);
			hs = encode_crypto_packet(c, &p, QC_HANDSHAKE, 0, NULL, 0, 0);
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
		if (!c->handshake_acknowledged) {
			*(p.p++) = CRYPTO;
			*(p.p++) = 0; // offset
			p.p += 2; // length
			uint8_t *fin_start = p.p;
			if (encode_finished(&p, c->client_finished, digest_size(c->cipher->hash))) {
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
			if (!c->handshake_acknowledged) {
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
		}

		// padding
		if (!c->handshake_acknowledged) {
			size_t pad = (size_t)(p.e - p.p) - QUIC_TAG_SIZE;
			memset(p.p, PADDING, pad);
			p.p += pad;
		}

		// tag
		uint8_t *tag = p.p;
		p.p += QUIC_TAG_SIZE;

		const qcipher_class **cipher = &pkts->tkey.u.vtable;
		(*cipher)->encrypt(cipher, pkts->tx_next, pkts->tkey.data_iv, pkt_begin, enc_begin, tag);
		(*cipher)->protect(cipher, packet_number, (size_t)(enc_begin - packet_number), (size_t)(p.p - packet_number));

		qtx_packet_t *pkt = &pkts->sent[pkts->tx_next % pkts->sent_len];
		if ((*c->iface)->send(c->iface, NULL, 0, buf, (size_t)(p.p - buf), &pkt->sent)) {
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
		insert_stream_packet(s, pkt);
		pkts->tx_next++;
		c->finished_sent = true;

		if (!s) {
			return;
		} else if (!qbuf_next_valid(&s->tx, &off)) {
			s->flags &= ~QSTREAM_TX_DIRTY;
			return;
		}
	}
}

static void send_data(qconnection_t *c) {
	if (!c->handshake_complete) {
		return;
	}

	for (qstream_t *s = c->tx_streams; s != NULL; s = s->next) {
		if (s->flags & QSTREAM_TX_DIRTY) {
			send_stream(c, s);
		}
	}

	for (int uni = 0; uni <= 1; uni++) {
		while (c->pending_streams[uni].first && c->pending_streams[uni].next < c->pending_streams[uni].max) {
			qstream_t *s = c->pending_streams[uni].first;
			c->pending_streams[uni].first = s->next;
			if (s->next) {
				s->next->prev = NULL;
			} else {
				c->pending_streams[uni].last = NULL;
			}
			insert_local_stream(c, s, uni);
			send_stream(c, s);
		}
	}

	if (!c->finished_sent) {
		send_stream(c, NULL);
	}
}

void qc_add_stream(qconnection_t *c, qstream_t *s) {
	int uni = s->rx.size ? 0 : 1;
	if (c->handshake_complete && c->pending_streams[uni].next < c->pending_streams[uni].max) {
		insert_local_stream(c, s, uni);
		send_stream(c, s);
	} else {
		s->prev = c->pending_streams[uni].last;
		s->next = NULL;
		if (s->prev) {
			s->prev->next = s;
		} else {
			c->pending_streams[uni].first = s;
		}
		c->pending_streams[uni].last = s;
	}
}

int qc_timeout(qconnection_t *c, qmicrosecs_t now, qmicrosecs_t *ptimeout) {
	long delta = (long)(c->idle_timer - now);
	if (delta <= 0) {
		return -1;
	}
	c->rtt *= 2;
	c->retransmit_timer = now + 2 * c->rtt;
	calculate_timeout(c, ptimeout);
	LOG(c->debug, "RTT %d ms, timeout %08x, now %08x", c->rtt / 1000, *ptimeout, now);
	return 0;
}






