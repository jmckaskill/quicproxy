#include "internal.h"

static const char prng_nonce[] = "quicproxy prng nonce";


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
	for (uint64_t num = from; num <= to; num++) {
		if (num < b->tx_oldest) {
			continue;
		}

		qtx_packet_t *pkt = &b->sent[num % b->sent_len];
		if (pkt->stream) {
			q_ack_stream(c, pkt);
		}
		uint8_t flags = pkt->flags;
		if (flags & QTX_PKT_MAX_DATA) {
			q_ack_max_data(c, pkt);
		}
		if (flags & QTX_PKT_MAX_ID_UNI) {
			q_ack_max_id(c, pkt);
		}
		if (flags & QTX_PKT_MAX_ID_BIDI) {
			q_ack_max_id(c, pkt);
		}
		if (flags & QTX_PKT_CLOSE) {
			q_ack_close(c);
		}
		if (flags & QTX_PKT_CRYPTO) {
			q_ack_crypto(c, pkt);
		}
		if (flags & QTX_PKT_RETRANSMIT) {
			c->retransmit_packets--;
		}
		pkt->off = UINT64_MAX;

		if (num == b->tx_oldest) {
			update_oldest_packet(b);
		}
	}
}

static void process_gap_range(qconnection_t *c, enum qcrypto_level level, uint64_t from, uint64_t to, uint64_t largest, tick_t now) {
	qpacket_buffer_t *b = &c->pkts[level];
	for (uint64_t num = from; num <= to; num++) {
		if (num < b->tx_oldest) {
			continue;
		}
		tick_t lost = now - (c->srtt * 9 / 8);
		qtx_packet_t *pkt = &b->sent[num % b->sent_len];
		if (level == QC_PROTECTED && num + 3 > largest && (int32_t)(pkt->sent - lost) > 0) {
			// the packet is too new to be lost yet by either the fast retransmit or early retransmit
			continue;
		}
		// packet is lost
		if (pkt->stream) {
			q_lost_stream(c, pkt);
		}
		uint8_t flags = pkt->flags;
		if (flags & QTX_PKT_MAX_DATA) {
			q_lost_max_data(c, pkt);
		}
		if (flags & QTX_PKT_MAX_ID_UNI) {
			q_lost_max_id(c, 1);
		}
		if (flags & QTX_PKT_MAX_ID_BIDI) {
			q_lost_max_id(c, 0);
		}
		if (flags & QTX_PKT_CLOSE) {
			q_lost_close(c, now);
		}
		if (flags & QTX_PKT_NEW_ID) {
			q_lost_new_id(c, pkt);
		}
		if (flags & QTX_PKT_RETIRE_ID) {
			q_lost_retire_id(c, pkt);
		}
		if (flags & QTX_PKT_CRYPTO) {
			q_lost_crypto(c, pkt);
		}
		if (flags & QTX_PKT_RETRANSMIT) {
			c->retransmit_packets--;
		}
		pkt->off = UINT64_MAX;

		if (num == b->tx_oldest) {
			update_oldest_packet(b);
		}
	}
}

static int decode_ack(qconnection_t *c, enum qcrypto_level level, uint8_t hdr, qslice_t *s, tick_t rxtime) {
	uint64_t largest, raw_delay, count, first;
	if (decode_varint(s, &largest)
		|| decode_varint(s, &raw_delay)
		|| decode_varint(s, &count)
		|| decode_varint(s, &first)
		|| first > largest) {
		return QC_ERR_FRAME_ENCODING;
	}

	if (hdr & ACK_ECN_FLAG) {
		uint64_t ect0, ect1, ce;
		if (decode_varint(s, &ect0) 
			|| decode_varint(s, &ect1) 
			|| decode_varint(s, &ce)) {
			return QC_ERR_FRAME_ENCODING;
		}
	}

	qpacket_buffer_t *b = &c->pkts[level];
	if (largest < b->tx_oldest) {
		return 0;
	} else if (largest >= b->tx_next) {
		return QC_ERR_FRAME_ENCODING;
	}

	qtx_packet_t *pkt = &b->sent[largest % b->sent_len];

	if (pkt->off != UINT64_MAX) {
		tickdiff_t latest_rtt = (tickdiff_t)(rxtime - pkt->sent);
		c->min_rtt = MIN(c->min_rtt, latest_rtt);

		tickdiff_t delay = raw_delay << c->peer_cfg.ack_delay_exponent;
		if (delay < latest_rtt) {
			latest_rtt -= delay;
		}
		if (c->srtt) {
			tickdiff_t rttvar_sample = abs(c->srtt - latest_rtt);
			c->rttvar = (3 * c->rttvar + rttvar_sample) / 4;
			c->srtt = (7 * c->srtt + latest_rtt) / 8;
		} else {
			c->srtt = latest_rtt;
			c->rttvar = latest_rtt / 2;
		}
	}

	uint64_t next = largest - first;
	process_ack_range(c, level, next, largest);

	while (count) {
		uint64_t gap, block;
		if (decode_varint(s, &gap) || decode_varint(s, &block) || gap + 2 + block > next) {
			return QC_ERR_FRAME_ENCODING;
		}
		uint64_t to = next - gap - 2;
		uint64_t from = to - block;
		process_gap_range(c, level, to, next - 1, largest, rxtime);
		process_ack_range(c, level, from, to);
		next = from;
		count--;
	}

	if (b->tx_oldest < next) {
		process_gap_range(c, level, b->tx_oldest, next - 1, largest, rxtime);
	}

	if (!c->retransmit_packets && c->peer_verified) {
		// cancel the tail loss probe, we've got all our packets acknowledged
		cancel_apc(c->dispatcher, &c->rx_timer);
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

static int process_protected_frame(qconnection_t *c, qslice_t *s, tick_t rxtime) {
	uint8_t hdr = *(s->p++);
	if ((hdr & STREAM_MASK) == STREAM) {
		return q_decode_stream(c, hdr, s, rxtime);
	} else {
		switch (hdr) {
		default:
			return QC_ERR_FRAME_ENCODING;
		case PADDING:
			s->p = find_non_padding(s->p, s->e);
			return 0;
		case RST_STREAM:
			return q_decode_reset(c, &s);
		case CONNECTION_CLOSE:
		case APPLICATION_CLOSE:
			return q_decode_close(c, hdr, s);
		case MAX_DATA:
			return q_decode_max_data(c, s);
		case MAX_STREAM_DATA:
			return q_decode_stream_data(c, s);
		case MAX_STREAM_ID:
			return q_decode_max_id(c, s);
		case PING:
			LOG(c->local_cfg->debug, "RX PING");
			q_async_send_ack(c, rxtime + QUIC_SHORT_ACK_TIMEOUT);
			return 0;
		case BLOCKED: {
			uint64_t off;
			if (decode_varint(s, &off)) {
				return QC_ERR_FRAME_ENCODING;
			}
			LOG(c->local_cfg->debug, "RX BLOCKED Off %"PRIu64, off);
			return 0;
		}
		case STREAM_BLOCKED: {
			uint64_t id, off;
			if (decode_varint(s, &id) || decode_varint(s, &off)) {
				return QC_ERR_FRAME_ENCODING;
			}
			LOG(c->local_cfg->debug, "RX STREAM BLOCKED ID %"PRIu64" Off %"PRIu64, id, off);
			return 0;
		}
		case STREAM_ID_BLOCKED: {
			uint64_t id;
			if (decode_varint(s, &id)) {
				return QC_ERR_FRAME_ENCODING;
			}
			LOG(c->local_cfg->debug, "RX STREAM ID BLOCKED MAX ID %"PRIu64, id);
			return 0;
		}
		case NEW_CONNECTION_ID: {
			if (s->p == s->e) {
				return QC_ERR_FRAME_ENCODING;
			}
			size_t len = *(s->p++);
			uint64_t seqnum;
			if (decode_varint(s, &seqnum) || len < 4 || len > 18 || s->p + len + 16 > s->e) {
				return QC_ERR_FRAME_ENCODING;
			}
			s->p += len + 16;
			LOG(c->local_cfg->debug, "RX NEW ID Seq %"PRIu64, seqnum);
			return 0;
		}
		case RETIRE_CONNECTION_ID: {
			uint64_t seqnum;
			if (decode_varint(s, &seqnum)) {
				return QC_ERR_FRAME_ENCODING;
			}
			LOG(c->local_cfg->debug, "RX RETIRE ID Seq %"PRIu64, seqnum);
			return 0;
		}
		case STOP_SENDING:
			return q_decode_stop(c, s);
		case ACK | ACK_ECN_FLAG:
		case ACK:
			LOG(c->local_cfg->debug, "RX ACK");
			return decode_ack(c, QC_PROTECTED, hdr, &s, rxtime);
		case PATH_RESPONSE:
		case PATH_CHALLENGE: {
			if (s->p + 8 > s->e) {
				return QC_ERR_FRAME_ENCODING;
			}
			s->p += 8;
			LOG(c->local_cfg->debug, "RX PATH CHLG/RESP");
			return 0;
		}
		case NEW_TOKEN: {
			uint64_t len;
			if (decode_varint(s, &len) || len > (s->e - s->p)) {
				return QC_ERR_FRAME_ENCODING;
			}
			LOG(c->local_cfg->debug, "RX TOKEN");
			return 0;
		}
		case CRYPTO:
			LOG(c->local_cfg->debug, "RX CRYPTO");
			q_async_send_ack(c, rxtime, true);
			return q_decode_crypto(c, QC_PROTECTED, &s);
		}
	}
}

static int process_handshake_frame(qconnection_t *c, qslice_t *s, enum qcrypto_level level, tick_t rxtime) {
	uint8_t hdr = *(s->p++);
	switch (hdr) {
	default:
		return QC_ERR_DROP;
	case PADDING:
		s->p = find_non_padding(s->p, s->e);
		return 0;
	case CONNECTION_CLOSE:
	case APPLICATION_CLOSE:
		return q_decode_close(c, hdr, s);
	case ACK | ACK_ECN_FLAG:
	case ACK:
		LOG(c->local_cfg->debug, "RX ACK");
		return decode_ack(c, level, hdr, &s, rxtime);
	case CRYPTO:
		LOG(c->local_cfg->debug, "RX CRYPTO");
		q_async_send_ack(c, rxtime, true);
		return q_decode_crypto(c, level, &s);
	}
}

static int process_packet(qconnection_t *c, qslice_t s, enum qcrypto_level level, tick_t rxtime) {
	int err = 0;
	while (!err && s.p < s.e) {
		if (level == QC_PROTECTED && c->peer_verified) {
			err = process_protected_frame(c, &s, rxtime);
		} else {
			err = process_handshake_frame(c, &s, level, rxtime);
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

int qc_decode_request(qconnect_request_t *h, void *buf, size_t buflen, tick_t rxtime, const qconnection_cfg_t *cfg) {
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
			if (decode_client_hello(&s, h, cfg)) {
				return QC_PARSE_ERROR;
			}
			h->chello_size = (size_t)len;
			have_hello = true;
			break;
		}
		}
	}

	h->rxtime = rxtime;
	h->server_cfg = cfg;
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
			qslice_t pkt = { s.p, s.p + (size_t)paysz };
			s.p = pkt.e;
			if (!key.vtable) {
				continue;
			}

			uint64_t pktnum;
			if (decrypt_packet(&key.vtable, pkt_begin, &pkt, &pktnum)) {
				continue;
			}
			q_start_idle_timer(c, rxtime);
			int err = process_packet(c, pkt, level, rxtime);
			if (err == QC_ERR_DROP) {
				continue;
			} else if (err) {
				set_closing(c, err);
				return;
			}
			receive_packet(c, level, pktnum, rxtime);
			send_data(c, 0, rxtime);

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
			q_start_idle_timer(c, rxtime);
			int err = process_packet(c, s, QC_PROTECTED, rxtime);
			if (!err) {
				receive_packet(c, QC_PROTECTED, pktnum, rxtime);
				send_data(c, 0, rxtime);
			} else if (err != QC_ERR_DROP) {
				set_closing(c, err);
			}
			return;
		}
	}
}




//////////////////////////////
// Initialization

static int init_connection(qconnection_t *c, bool is_client, br_prng_seeder seedfn, void *buf, size_t size) {
	memset(c, 0, sizeof(*c));
	br_hmac_drbg_init(&c->rand, &br_sha256_vtable, prng_nonce, sizeof(prng_nonce));
	if (!seedfn) {
		seedfn = br_prng_seeder_system(NULL);
	}
	if (!seedfn || !seedfn(&c->rand.vtable)) {
		return -1;
	}

	char *s = (char*)ALIGN_UP(uintptr_t, (uintptr_t)buf, 8);
	char *e = (char*)ALIGN_DOWN(uintptr_t, (uintptr_t)buf + size, 8);

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

	size_t hspkts = sizeof(qtx_packet_t) * (c->pkts[QC_INITIAL].sent_len + c->pkts[QC_HANDSHAKE].sent_len);
	if (s + hspkts >= e) {
		return -1;
	}
	c->pkts[QC_INITIAL].sent = (qtx_packet_t*)s;
	c->pkts[QC_HANDSHAKE].sent = (qtx_packet_t*)s + c->pkts[QC_INITIAL].sent_len;
	c->pkts[QC_PROTECTED].sent = (qtx_packet_t*)s + hspkts;
	c->pkts[QC_PROTECTED].sent_len = (size_t)(e - s - hspkts) / sizeof(qtx_packet_t);

	br_sha256_init(&c->msg_sha256);
	br_sha384_init(&c->msg_sha384);
	c->srtt = QUIC_DEFAULT_RTT;
	c->min_rtt = INT32_MAX;
	c->peer_cfg.ack_delay_exponent = QUIC_ACK_DELAY_SHIFT;

	return 0;
}

static void generate_id(const br_prng_class **r, uint8_t *id) {
	id[0] = DEFAULT_SERVER_ID_LEN;
	(*r)->generate(r, id + 1, DEFAULT_SERVER_ID_LEN);
	memset(id + 1 + DEFAULT_SERVER_ID_LEN, 0, QUIC_ADDRESS_SIZE - DEFAULT_SERVER_ID_LEN - 1);
}

int qc_connect(qconnection_t *c, dispatcher_t *d, const qinterface_t **vt, const char *server_name, const qconnection_cfg_t *cfg, void *buf, size_t size) {
	if (init_connection(c, true, cfg->seeder, buf, size)) {
		return -1;
	}
	c->iface = vt;
	c->dispatcher = d;
	c->local_cfg = cfg;
	c->server_name = server_name;
	generate_id(&c->rand.vtable, c->peer_id);
	generate_id(&c->rand.vtable, c->local_id);
	init_client_decoder(c);

	// generate a private key for the high priority groups
	const br_ec_impl *ec = br_ec_get_default();
	for (size_t i = 0, knum = MIN(QUIC_MAX_KEYSHARE, strlen(cfg->groups)); i < knum; i++) {
		if (!br_ec_keygen(&c->rand.vtable, ec, &c->keys[i], c->key_data[i], cfg->groups[i])) {
			return -1;
		}
	}

	// generate the client random
	c->rand.vtable->generate(&c->rand.vtable, c->client_random, sizeof(c->client_random));

	tick_t now = 0;
	if (send_client_hello(c, &now)) {
		return -1;
	}


	return 0;
}

int qc_accept(qconnection_t *c, dispatcher_t *d, const qinterface_t **vt, const qconnect_request_t *h, const qsigner_class *const *s, void *buf, size_t size) {
	if (init_connection(c, false, h->server_cfg->seeder, buf, size)) {
		return -1;
	}
	c->iface = vt;
	c->dispatcher = d;
	c->local_cfg = h->server_cfg;
	c->peer_cfg = h->client_cfg;
	c->signer = s;
	memcpy(c->peer_id, h->source, QUIC_ADDRESS_SIZE);
	memcpy(c->local_id, h->destination, QUIC_ADDRESS_SIZE);
	memcpy(c->client_random, h->client_random, QUIC_RANDOM_SIZE);
	init_server_decoder(c);

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
	const br_hash_class **msgs = init_cipher(c, h->cipher);
	if (msgs == NULL) {
		return -1;
	}
	(*msgs)->update(msgs, h->chello, h->chello_size);

	// send server hello
	tick_t sent;
	receive_packet(c, QC_INITIAL, 0, h->rxtime);
	if (send_server_hello(c, &h->key, h->rxtime)) {
		return -1;
	}

	c->rx_timer_count = 0;
	q_start_handshake_timer(c, h->rxtime);
	q_start_idle_timer(c, h->rxtime);
	return 0;
}

void qc_move(qconnection_t *c, dispatcher_t *d) {
	if (c->dispatcher != d) {
		move_apc(c->dispatcher, d, &c->tx_timer);
		move_apc(c->dispatcher, d, &c->rx_timer);
		move_apc(c->dispatcher, d, &c->idle_timer);
		c->dispatcher = d;
	}
}

void qc_close(qconnection_t *c) {
	cancel_apc(c->dispatcher, &c->tx_timer);
	cancel_apc(c->dispatcher, &c->rx_timer);
	cancel_apc(c->dispatcher, &c->idle_timer);
}

