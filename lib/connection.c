#include "internal.h"
#include <math.h>



////////////////////////////////////////////////
// ACK Processing

static void update_oldest_packet(qpacket_buffer_t *b) {
	do {
		b->tx_oldest++;
	} while (b->tx_oldest < b->tx_next && b->sent[b->tx_oldest % b->sent_len].off == UINT64_MAX);
}

// from & to form a closed range
static void process_ack_range(struct connection *c, qpacket_buffer_t *b, uint64_t from, uint64_t to) {
	for (uint64_t num = from; num <= to; num++) {
		if (num < b->tx_oldest) {
			continue;
		}

		qtx_packet_t *pkt = &b->sent[num % b->sent_len];
		q_cwnd_ack(c, num, pkt);
		if (pkt->stream) {
			q_ack_stream(c, pkt);
		}
		unsigned flags = pkt->flags;
		if (flags & (QPKT_MAX_DATA | QPKT_MAX_ID_BIDI | QPKT_MAX_ID_UNI)) {
			q_ack_scheduler(c, pkt);
		}
		if (flags & QPKT_CLOSE) {
			q_ack_close(c);
		}
		if (flags & QPKT_CRYPTO) {
			q_ack_crypto(c, pkt);
		}
		if (flags & QPKT_RETRANSMIT) {
			c->retransmit_packets--;
		}
		pkt->off = UINT64_MAX;

		if (num == b->tx_oldest) {
			update_oldest_packet(b);
		}
	}
}

static void process_gap_range(struct connection *c, qpacket_buffer_t *b, uint64_t from, uint64_t to, uint64_t largest, tick_t now) {
	for (uint64_t num = from; num <= to; num++) {
		if (num < b->tx_oldest) {
			continue;
		}
		tick_t lost = now - (c->srtt * 9 / 8);
		qtx_packet_t *pkt = &b->sent[num % b->sent_len];
		if (b == &c->prot_pkts && num + 3 > largest && (int32_t)(pkt->sent - lost) > 0) {
			// the packet is too new to be lost yet by either the fast retransmit or early retransmit
			continue;
		}
		// packet is lost
		q_cwnd_lost(c, pkt);
		if (pkt->stream) {
			q_lost_stream(c, pkt);
		}
		unsigned flags = pkt->flags;
		if (flags & (QPKT_MAX_DATA | QPKT_MAX_ID_BIDI | QPKT_MAX_ID_UNI)) {
			q_lost_scheduler(c, pkt);
		}
		if (flags & QPKT_CLOSE) {
			q_lost_close(c, now);
		}
		if (flags & QPKT_CRYPTO) {
			q_lost_crypto(c, pkt);
		}
		if (flags & QPKT_RETRANSMIT) {
			c->retransmit_packets--;
		}
		pkt->off = UINT64_MAX;

		if (num == b->tx_oldest) {
			update_oldest_packet(b);
		}
	}
}

static int decode_ack(struct connection *c, enum qcrypto_level level, uint8_t hdr, qslice_t *s, tick_t rxtime) {
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
		q_cwnd_ecn(c, largest, ce);
	}

	qpacket_buffer_t *b = (level == QC_PROTECTED) ? &c->prot_pkts : &((struct handshake*)c)->pkts[level];
	assert(level == QC_PROTECTED || !c->peer_verified);
	if (largest < b->tx_oldest) {
		return 0;
	} else if (largest >= b->tx_next) {
		return QC_ERR_FRAME_ENCODING;
	}

	uint64_t largest_lost = UINT64_MAX;
	qtx_packet_t *pkt = &b->sent[largest % b->sent_len];

	if (pkt->off != UINT64_MAX) {
		tickdiff_t latest_rtt = (tickdiff_t)(rxtime - pkt->sent);
		c->min_rtt = MIN(c->min_rtt, latest_rtt);

		tickdiff_t delay = q_decode_ack_delay(raw_delay, (level == QC_PROTECTED ? c->peer_cfg.ack_delay_exponent : 0));
		if (delay < latest_rtt) {
			latest_rtt -= delay;
		}
		if (c->have_srtt) {
			tickdiff_t rttvar_sample = abs(c->srtt - latest_rtt);
			c->rttvar = (3 * c->rttvar + rttvar_sample) / 4;
			c->srtt = (7 * c->srtt + latest_rtt) / 8;
		} else {
			c->srtt = latest_rtt;
			c->rttvar = latest_rtt / 2;
			c->have_srtt = true;
		}
	}

	uint64_t next = largest - first;
	process_ack_range(c, b, next, largest);

	while (count) {
		uint64_t gap, block;
		if (decode_varint(s, &gap) || decode_varint(s, &block) || gap + 2 + block > next) {
			return QC_ERR_FRAME_ENCODING;
		}
		uint64_t to = next - gap - 2;
		uint64_t from = to - block;
		process_gap_range(c, b, to, next - 1, largest, rxtime);
		process_ack_range(c, b, from, to);
		largest_lost = from;
		next = from;
		count--;
	}

	if (b->tx_oldest < next) {
		process_gap_range(c, b, b->tx_oldest, next - 1, largest, rxtime);
		largest_lost = b->tx_oldest;
	}

	if (largest_lost != UINT64_MAX) {
		q_cwnd_largest_lost(c, largest_lost);
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

static int process_protected_frame(struct connection *c, qslice_t *s, tick_t rxtime) {
	uint8_t hdr = *(s->p++);
	if ((hdr & STREAM_MASK) == STREAM) {
		q_async_ack(c, rxtime);
		return q_decode_stream(c, hdr, s);
	} else {
		switch (hdr) {
		default:
			return QC_ERR_FRAME_ENCODING;
		case PADDING:
			s->p = find_non_padding(s->p, s->e);
			return 0;
		case RST_STREAM:
			q_async_ack(c, rxtime);
			return q_decode_reset(c, s);
		case CONNECTION_CLOSE:
		case APPLICATION_CLOSE:
			q_draining_ack(c, rxtime);
			return q_decode_close(c, hdr, s, rxtime);
		case MAX_DATA:
			q_async_ack(c, rxtime);
			return q_decode_max_data(c, s);
		case MAX_STREAM_DATA:
			q_async_ack(c, rxtime);
			return q_decode_stream_data(c, s);
		case MAX_STREAM_ID:
			q_async_ack(c, rxtime);
			return q_decode_max_id(c, s);
		case PING:
			LOG(c->local_cfg->debug, "RX PING");
			q_fast_async_ack(c, rxtime);
			return 0;
		case BLOCKED: {
			uint64_t off;
			if (decode_varint(s, &off)) {
				return QC_ERR_FRAME_ENCODING;
			}
			q_async_ack(c, rxtime);
			LOG(c->local_cfg->debug, "RX BLOCKED Off %"PRIu64, off);
			return 0;
		}
		case STREAM_BLOCKED: {
			uint64_t id, off;
			if (decode_varint(s, &id) || decode_varint(s, &off)) {
				return QC_ERR_FRAME_ENCODING;
			}
			q_async_ack(c, rxtime);
			LOG(c->local_cfg->debug, "RX STREAM BLOCKED ID %"PRIu64" Off %"PRIu64, id, off);
			return 0;
		}
		case STREAM_ID_BLOCKED: {
			uint64_t id;
			if (decode_varint(s, &id)) {
				return QC_ERR_FRAME_ENCODING;
			}
			q_async_ack(c, rxtime);
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
			q_async_ack(c, rxtime);
			return 0;
		}
		case RETIRE_CONNECTION_ID: {
			uint64_t seqnum;
			if (decode_varint(s, &seqnum)) {
				return QC_ERR_FRAME_ENCODING;
			}
			LOG(c->local_cfg->debug, "RX RETIRE ID Seq %"PRIu64, seqnum);
			q_async_ack(c, rxtime);
			return 0;
		}
		case STOP_SENDING:
			q_async_ack(c, rxtime);
			return q_decode_stop(c, s);
		case ACK | ACK_ECN_FLAG:
		case ACK:
			LOG(c->local_cfg->debug, "RX ACK");
			return decode_ack(c, QC_PROTECTED, hdr, s, rxtime);
		case PATH_RESPONSE:
		case PATH_CHALLENGE: {
			if (s->p + 8 > s->e) {
				return QC_ERR_FRAME_ENCODING;
			}
			s->p += 8;
			LOG(c->local_cfg->debug, "RX PATH CHLG/RESP");
			q_fast_async_ack(c, rxtime);
			return 0;
		}
		case NEW_TOKEN: {
			uint64_t len;
			if (decode_varint(s, &len) || len > (uint64_t)(s->e - s->p)) {
				return QC_ERR_FRAME_ENCODING;
			}
			LOG(c->local_cfg->debug, "RX TOKEN");
			q_async_ack(c, rxtime);
			return 0;
		}
		case CRYPTO:
			LOG(c->local_cfg->debug, "RX CRYPTO");
			q_fast_async_ack(c, rxtime);
			return q_decode_crypto(c, QC_PROTECTED, s, rxtime);
		}
	}
}

static int process_handshake_frame(struct connection *c, qslice_t *s, enum qcrypto_level level, tick_t rxtime) {
	uint8_t hdr = *(s->p++);
	switch (hdr) {
	default:
		return QC_ERR_DROP;
	case PADDING:
		s->p = find_non_padding(s->p, s->e);
		return 0;
	case CONNECTION_CLOSE:
	case APPLICATION_CLOSE:
		q_fast_async_ack(c, rxtime);
		return q_decode_close(c, hdr, s, rxtime);
	case ACK | ACK_ECN_FLAG:
	case ACK:
		LOG(c->local_cfg->debug, "RX ACK");
		return decode_ack(c, level, hdr, s, rxtime);
	case CRYPTO:
		LOG(c->local_cfg->debug, "RX CRYPTO");
		q_fast_async_ack(c, rxtime);
		return q_decode_crypto(c, level, s, rxtime);
	}
}

static int process_packet(struct connection *c, qslice_t s, enum qcrypto_level level, tick_t rxtime) {
	int err = 0;
	while (!err && s.p < s.e) {
		if (!c->peer_verified) {
			err = process_handshake_frame(c, &s, level, rxtime);
		} else {
			assert(level == QC_PROTECTED);
			err = process_protected_frame(c, &s, rxtime);
		}
	}
	return err;
}

int qc_get_destination(void *buf, size_t len, uint8_t *out) {
	// this should only rely on the invariants as we don't check the version yet
	uint8_t *u = buf;
	if (len < 1 + DEFAULT_SERVER_ID_LEN) {
		return QC_PARSE_ERROR;
	}
	memset(out, 0, QUIC_ADDRESS_SIZE);
	if (u[0] & LONG_HEADER_FLAG) {
		out[0] = decode_id_len(u[5] >> 4);
		if (len < (size_t)(6 + out[0])) {
			return QC_PARSE_ERROR;
		}
		memcpy(out + 1, u + 6, out[0]);
	} else {
		out[0] = DEFAULT_SERVER_ID_LEN;
		memcpy(out + 1, u + 1, DEFAULT_SERVER_ID_LEN);
	}
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

int qc_decode_request(qconnect_request_t *req, void *buf, size_t buflen, tick_t rxtime, const qconnection_cfg_t *cfg) {
	memset(req, 0, sizeof(*req));
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
	req->destination[0] = decode_id_len(*s.p >> 4);
	req->source[0] = decode_id_len(*s.p & 0xF);
	s.p++;
	if (req->destination[0] != DEFAULT_SERVER_ID_LEN) {
		return QC_STATELESS_RETRY;
	}

	// destination
	memcpy(req->destination + 1, s.p, DEFAULT_SERVER_ID_LEN);
	s.p += DEFAULT_SERVER_ID_LEN;

	// source
	memcpy(req->source + 1, s.p, req->source[0]);
	s.p += req->source[0];

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
	init_initial_cipher(&key, true, req->destination);
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
			req->chello = s.p;
			if (decode_client_hello(&s, req, cfg)) {
				return QC_PARSE_ERROR;
			}
			req->chello_size = (size_t)len;
			have_hello = true;
			break;
		}
		}
	}

	req->rxtime = rxtime;
	req->server_cfg = cfg;
	return have_hello ? QC_NO_ERROR : QC_PARSE_ERROR;
}

void qc_recv(qconnection_t *cin, void *buf, size_t len, const struct sockaddr *sa, socklen_t salen, tick_t rxtime) {
	struct connection *c = (struct connection*)cin;
	qslice_t s;
	s.p = buf;
	s.e = s.p + len;

	// Be careful that we only shutdown the connection if we encounter
	// an error after verifying the tag. We want to be sure it's actually
	// from the remote and not a fake message.

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

			if (hdr == INITIAL_PACKET) {
				uint64_t toksz;
				if (decode_varint(&s, &toksz) || toksz > (uint64_t)(s.e - s.p)) {
					return;
				}
				s.p += (size_t)toksz;
			}

			uint64_t paysz;
			if (decode_varint(&s, &paysz) || paysz > (uint64_t)(s.e - s.p)) {
				return;
			}
			qslice_t pkt = { s.p, s.p + (size_t)paysz };
			s.p = pkt.e;

			enum qcrypto_level level;
			qcipher_compat key;

			if (c->peer_verified) {
				continue;
			} else if (hdr == INITIAL_PACKET) {
				init_initial_cipher(&key.aes_gcm, !c->is_client, c->is_client ? c->peer_id : c->local_id);
				level = QC_INITIAL;
			} else if (hdr == HANDSHAKE_PACKET && c->prot_rx.vtable) {
				struct handshake *h = (struct handshake*)c;
				c->prot_rx.vtable->init(&key.vtable, h->hs_rx);
				level = QC_HANDSHAKE;
			} else {
				continue;
			}

			uint64_t pktnum;
			if (decrypt_packet(&key.vtable, pkt_begin, &pkt, &pktnum)) {
				continue;
			}
			q_start_idle_timer(c, rxtime);
			int err = process_packet(c, pkt, level, rxtime);
			if (!err) {
				q_receive_packet(c, level, pktnum, rxtime);
			} else if (err != QC_ERR_DROP) {
				q_internal_shutdown(c, err, rxtime);
				return;
			}

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
				q_receive_packet(c, QC_PROTECTED, pktnum, rxtime);
			} else if (err != QC_ERR_DROP) {
				q_internal_shutdown(c, err, rxtime);
			}
			return;
		}
	}
}




//////////////////////////////
// Initialization

static const char prng_nonce[] = "quicproxy prng nonce";

static int init_connection(struct handshake *h, size_t csz, dispatcher_t *d, const qconnection_cfg_t *cfg) {
	br_hmac_drbg_init(&h->rand, &br_sha256_vtable, prng_nonce, sizeof(prng_nonce));
	br_hmac_drbg_update(&h->rand, &h, sizeof(h));
	br_hmac_drbg_update(&h->rand, &d->last_tick, sizeof(d->last_tick));
	br_prng_seeder seedfn = cfg->seeder;
	if (!seedfn) {
		seedfn = br_prng_seeder_system(NULL);
	}
	if (!seedfn || !seedfn(&h->rand.vtable)) {
		return -1;
	}

	h->c.srtt = QUIC_DEFAULT_RTT;
	h->c.min_rtt = INT32_MAX;
	h->c.peer_cfg.ack_delay_exponent = QUIC_ACK_DELAY_SHIFT;
	h->c.dispatcher = d;
	h->conn_buf_end = (uint8_t*)h + csz;
	return 0;
}

static void generate_id(const br_prng_class **r, uint8_t *id) {
	id[0] = DEFAULT_SERVER_ID_LEN;
	(*r)->generate(r, id + 1, DEFAULT_SERVER_ID_LEN);
	memset(id + 1 + DEFAULT_SERVER_ID_LEN, 0, QUIC_ADDRESS_SIZE - DEFAULT_SERVER_ID_LEN - 1);
}

int qc_connect(qconnection_t *cin, size_t csz, dispatcher_t *d, const qinterface_t **vt, const char *server_name, const qconnection_cfg_t *cfg) {
	struct connection *c = (struct connection*)cin;
	struct handshake *h = (struct handshake*)cin;
	struct client_handshake *ch = (struct client_handshake*)cin;
	if (csz < sizeof(*ch) + BR_EC_KBUF_PRIV_MAX_SIZE) {
		return -1;
	}
	memset(ch, 0, sizeof(*ch));
	if (init_connection(h, csz, d, cfg)) {
		return -1;
	}
	c->is_client = true;
	c->iface = vt;
	c->local_cfg = cfg;
	ch->server_name = server_name;
	generate_id(&h->rand.vtable, c->peer_id);
	generate_id(&h->rand.vtable, c->local_id);
	h->level = QC_INITIAL;
	h->state = SHELLO_START;
	h->pkts[QC_INITIAL].sent = ch->init_pkts;
	h->pkts[QC_INITIAL].sent_len = ARRAYSZ(ch->init_pkts);
	h->pkts[QC_HANDSHAKE].sent = ch->hs_pkts;
	h->pkts[QC_HANDSHAKE].sent_len = ARRAYSZ(ch->hs_pkts);

	// generate a private key for the high priority groups
	const br_ec_impl *ec = br_ec_get_default();
	size_t n = 0;
	while (cfg->groups[n] != 0 && &ch->keys[(n+1) * BR_EC_KBUF_PRIV_MAX_SIZE] <= h->conn_buf_end) {
		if (!br_ec_keygen(&h->rand.vtable, ec, NULL, &ch->keys[n * BR_EC_KBUF_PRIV_MAX_SIZE], cfg->groups[n])) {
			return -1;
		}
		n++;
	}
	ch->key_num = n;

	// generate the client random
	h->rand.vtable->generate(&h->rand.vtable, c->client_random, sizeof(c->client_random));

	tick_t now = 0;
	if (q_send_client_hello(ch, &now)) {
		return -1;
	}

	q_start_handshake(h, now);
	return 0;
}

int qc_accept(qconnection_t *cin, size_t csz, dispatcher_t *d, const qinterface_t **vt, const qconnect_request_t *req, const qsigner_class *const *signer) {
	struct connection *c = (struct connection*)cin;
	struct handshake *h = (struct handshake*)cin;
	struct server_handshake *sh = (struct server_handshake*)cin;
	if (csz < sizeof(*sh)) {
		return -1;
	}
	memset(sh, 0, sizeof(*sh));
	if (init_connection(h, csz, d, req->server_cfg)) {
		return -1;
	}
	c->is_client = false;
	c->iface = vt;
	c->local_cfg = req->server_cfg;
	c->peer_cfg = req->client_cfg;
	sh->signer = signer;
	memcpy(c->peer_id, req->source, QUIC_ADDRESS_SIZE);
	memcpy(c->local_id, req->destination, QUIC_ADDRESS_SIZE);
	memcpy(c->client_random, req->client_random, QUIC_RANDOM_SIZE);
	h->level = QC_PROTECTED;
	h->state = FINISHED_START;
	h->pkts[QC_INITIAL].sent = sh->init_pkts;
	h->pkts[QC_INITIAL].sent_len = ARRAYSZ(sh->init_pkts);
	h->pkts[QC_HANDSHAKE].sent = sh->hs_pkts;
	h->pkts[QC_HANDSHAKE].sent_len = ARRAYSZ(sh->hs_pkts);

	// key group
	if (!req->key.curve || !br_ec_keygen(&h->rand.vtable, br_ec_get_default(), &sh->sk, sh->key_data, req->key.curve)) {
		return -1;
	}

	// certificates
	sh->signature = choose_signature(signer, req->signatures);
	if (!sh->signature) {
		return -1;
	}

	// cipher & transcript
	const br_hash_class **msgs = init_cipher(h, req->cipher);
	if (msgs == NULL) {
		return -1;
	}
	req->cipher->hash->init(msgs);
	(*msgs)->update(msgs, req->chello, req->chello_size);

	// send server hello
	q_receive_packet(c, QC_INITIAL, 0, req->rxtime);
	if (q_send_server_hello(sh, &req->key, req->rxtime)) {
		return -1;
	}

	q_start_handshake(h, req->rxtime);
	return 0;
}

void qc_move(qconnection_t *cin, dispatcher_t *d) {
	struct connection *c = (struct connection*)cin;
	if (c->dispatcher != d) {
		move_apc(c->dispatcher, d, &c->tx_timer);
		move_apc(c->dispatcher, d, &c->rx_timer);
		move_apc(c->dispatcher, d, &c->idle_timer);
		c->dispatcher = d;
	}
}

void qc_close(qconnection_t *cin) {
	struct connection *c = (struct connection*)cin;
	cancel_apc(c->dispatcher, &c->tx_timer);
	cancel_apc(c->dispatcher, &c->rx_timer);
	cancel_apc(c->dispatcher, &c->idle_timer);
}

