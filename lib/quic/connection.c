#include "internal.h"
#include <math.h>


static const char prng_nonce[] = "quicproxy prng nonce";

static int seed_rand(br_hmac_drbg_context *c, const qconnection_cfg_t *cfg) {
	br_hmac_drbg_init(c, &br_sha256_vtable, prng_nonce, sizeof(prng_nonce));
	br_prng_seeder seedfn = cfg->seeder ? cfg->seeder : br_prng_seeder_system(NULL);
	return !seedfn || !seedfn(&c->vtable);
}

struct raw_prng {
	const br_prng_class *vtable;
	void *p;
	size_t sz;
};
static void update_raw(const br_prng_class **vt, const void *seed, size_t len) {
	struct raw_prng *r = (struct raw_prng*)vt;
	len = MIN(len, r->sz);
	r->p = append_mem(r->p, seed, len);
	r->sz -= len;
}
static const br_prng_class raw_vtable = {
	.update = &update_raw,
};

uint64_t q_generate_local_id(const qconnection_cfg_t *cfg, const br_prng_class **r) {
	if (cfg->generate_local_id) {
		return cfg->generate_local_id(cfg);
	}
	uint64_t ret;
	if (r) {
		(*r)->generate(r, &ret, sizeof(ret));
	} else {
		struct raw_prng raw = { &raw_vtable,&ret,sizeof(ret) };
		br_prng_seeder seedfn = cfg->seeder ? cfg->seeder : br_prng_seeder_system(NULL);
		if (!seedfn || !seedfn(&raw.vtable) || raw.sz) {
			return 0;
		}
	}
	return ret;
}

////////////////////////////////////////////////
// ACK Generation

static void receive_packet(struct connection *c, qpacket_buffer_t *s, uint64_t num, tick_t rxtime) {
	if (num > s->rx_next && (c->flags & QC_HS_COMPLETE)) {
		// out of order or dropped packet
		q_fast_async_ack(c, rxtime);
	}
	if (num >= s->rx_next) {
		q_reset_rx_timer(c, rxtime);
		s->rx_largest = rxtime;
	}
	// check to see if we should move the receive window forward
	if (num == s->rx_next) {
		// just one step
		s->rx_next = num + 1;
	} else if (num >= s->rx_next + 64) {
		// a long way
		s->rx_mask = 0;
		s->rx_next = num + 1;
	} else if (num > s->rx_next) {
		// a short way
		size_t shift = (size_t)(s->rx_next - ALIGN_DOWN(s->rx_next, (uint64_t)64));
		uint64_t mask = UINT64_C(1) << (num - s->rx_next);
		mask -= 1; // create a mask of n bits
		mask = (mask << shift) | (mask >> (64 - shift)); // and rotate left
		s->rx_mask &= ~mask; // and turn off the new bits
		s->rx_next = num + 1;
	}

	s->rx_mask |= UINT64_C(1) << (num & 63);
}

uint8_t *q_encode_ack(qpacket_buffer_t *pkts, uint8_t *p, tick_t now, unsigned exp) {
	static const unsigned max_blocks = 4;
	if (!pkts->rx_next) {
		return p;
	}

	*(p++) = ACK;

	// largest acknowledged
	p = q_encode_varint(p, pkts->rx_next - 1);

	// ack delay
	tickdiff_t delay = (tickdiff_t)(now - pkts->rx_largest);
	p = q_encode_varint(p, q_encode_ack_delay(delay, exp));

	// block count - fill out later
	uint8_t *pblock_count = p++;
	unsigned num_blocks = 0;

	// rotate left such that the latest (b.next-1) packet is in the top bit
	unsigned shift = (unsigned)(ALIGN_UP(pkts->rx_next, (uint64_t)64) - pkts->rx_next);
	uint64_t rx = (pkts->rx_mask << shift) | (pkts->rx_mask >> (64 - shift));

	// and shift the latest packet out
	rx <<= 1;

	// find the first block
	// rx is not all ones due to the shift above. Thus clz(~rx) is not called with a 0 value.
	unsigned first_block = clzl(~rx);
	*(p++) = (uint8_t)first_block;
	rx <<= first_block;

	while (rx && num_blocks < max_blocks) {
		// there is at least one 1 bit in rx
		// clz(rx) will return the number of 0s at the top (ie the gap)
		// clz(~(rx << gap)) will return the length of 1s section (ie the block)

		// find the gap
		unsigned gap = clzl(rx);
		*(p++) = (uint8_t)gap-1;
		rx <<= gap;

		// find the block
		unsigned block = clzl(~rx);
		*(p++) = (uint8_t)block-1;
		rx <<= block;

		num_blocks++;
	}

	*pblock_count = (uint8_t)num_blocks;
	return p;
}


////////////////////////////////////////////////
// ACK Processing

static void update_oldest_packet(qpacket_buffer_t *b) {
	do {
		b->tx_oldest++;
	} while (b->tx_oldest < b->tx_next && b->sent[b->tx_oldest % b->sent_len].off == UINT64_MAX);
}

static void ack_packet(struct connection *c, uint64_t num, qtx_packet_t *pkt) {
	unsigned flags = pkt->flags;
	if (flags & QPKT_CWND) {
		q_ack_cwnd(c, num, pkt);
	}
	if (flags & QPKT_PATH_RESPONSE) {
		q_ack_path_response(c);
	}
	if (pkt->stream) {
		q_ack_stream(c, pkt->stream, pkt);
	}
	pkt->off = UINT64_MAX;
}

static void lost_packet(struct connection *c, qtx_packet_t *pkt) {
	assert(pkt->off != UINT64_MAX);
	unsigned flags = pkt->flags;
	if (flags & QPKT_CWND) {
		q_lost_cwnd(c, pkt);
	}
	if (flags & QPKT_PATH_CHALLENGE) {
		q_lost_path_challenge(c);
	}
	if (pkt->stream) {
		q_lost_stream(c, pkt->stream, pkt);
	}
	pkt->off = UINT64_MAX;
}

static void process_gap(struct connection *c, qpacket_buffer_t *b, uint64_t num, uint64_t largest, tick_t now, int64_t *plargest) {
	qtx_packet_t *pkt = &b->sent[num % b->sent_len];
	if (num < b->tx_oldest || pkt->off == UINT64_MAX) {
		return;
	}
	tick_t lost = pkt->sent + (c->srtt * 9 / 8);
	if (num + 3 > largest && (tickdiff_t)(lost - now) > 0) {
		// the packet is too new to be lost yet by either fast retransmit or early retransmit
		return;
	}
	if ((pkt->flags & QPKT_CWND) && (int64_t)num > *plargest) {
		*plargest = (int64_t)num;
	}
	lost_packet(c, pkt);
	if (num == b->tx_oldest) {
		update_oldest_packet(b);
	}
}

static void update_rtt(struct connection *c, qpacket_buffer_t *b, uint64_t pktnum, tick_t now, tickdiff_t delay) {
	qtx_packet_t *pkt = &b->sent[pktnum % b->sent_len];

	if (pkt->off != UINT64_MAX && pktnum >= c->after_recovery) {
		tickdiff_t latest_rtt = (tickdiff_t)(now - pkt->sent);
		c->min_rtt = MIN(c->min_rtt, latest_rtt);

		if (delay < c->min_rtt) {
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
}

static int decode_ack(struct connection *c, qpacket_buffer_t *b, uint8_t hdr, qslice_t *s, tick_t rxtime) {
	uint64_t largest, raw_delay, num_blocks, first_block;
	if (q_decode_varint(s, &largest)
		|| q_decode_varint(s, &raw_delay)
		|| q_decode_varint(s, &num_blocks)
		|| q_decode_varint(s, &first_block)) {
		return QC_ERR_FRAME_ENCODING;
	}

	uint8_t *block_start = s->p;
	bool before = q_cwnd_allow(c);

	if (largest < b->tx_oldest) {
		return 0;
	} else if (largest >= b->tx_next) {
		return QC_ERR_FRAME_ENCODING;
	}

	if (b == &c->prot_pkts && !(c->flags & QC_FIN_ACKNOWLEDGED)) {
		// Until this point, the client will send the finished message in every
		// protected packet. Once the server has acknowledged one, we know that it
		// got the finished frame and the handshake is complete.
		LOG(c->local_cfg->debug, "client handshake complete");
		c->flags |= QC_FIN_ACKNOWLEDGED;
	}

	if (largest > b->tx_largest_acked) {
		b->tx_largest_acked = largest;
	}

	tickdiff_t delay = q_decode_ack_delay(raw_delay, (b == &c->prot_pkts ? c->peer_cfg.ack_delay_exponent : 0));
	update_rtt(c, b, largest, rxtime, delay);
	
	// Process ACKs first
	uint64_t smallest_new_ack = 0;
	bool have_new_ack = false;
	uint64_t num = largest + 1;
	uint64_t blocks_left = num_blocks;
	uint64_t pkts_left = first_block + 1;
	for (;;) {
		do {
			qtx_packet_t *pkt = &b->sent[(--num) % b->sent_len];
			if (num < b->tx_oldest) {
				break;
			} else if (pkt->off == UINT64_MAX) {
				continue;
			}
			smallest_new_ack = num;
			have_new_ack = true;
			ack_packet(c, num, pkt);
			if (num == b->tx_oldest) {
				update_oldest_packet(b);
				break;
			}
		} while (--pkts_left);

		if (blocks_left-- == 0) {
			break;
		}

		// num is now the smallest in the block
		uint64_t gap, block;
		if (q_decode_varint(s, &gap) || q_decode_varint(s, &block) || gap + block + 2 > num) {
			return QC_ERR_FRAME_ENCODING;
		}
		num -= gap + 1;
		pkts_left = block + 1;
	}

	if (have_new_ack) {
		// Then check for RTO verification
		if (c->rto_next && smallest_new_ack >= c->rto_next) {
			uint64_t lost_pkts = smallest_new_ack - b->tx_oldest;
			if (lost_pkts) {
				num = smallest_new_ack;
				do {
					qtx_packet_t *pkt = &b->sent[(--num) % b->sent_len];
					if (pkt->off != UINT64_MAX) {
						lost_packet(c, pkt);
					}
				} while (--lost_pkts);
			}
			q_reset_cwnd(c, smallest_new_ack);
			b->tx_oldest = smallest_new_ack;
			update_oldest_packet(b);
		}

		// Then process gaps
		bool have_cwnd_lost = false;
		tick_t lost_threshold = rxtime - (c->srtt * 9 / 8);
		s->p = block_start;
		num = largest - first_block;
		blocks_left = num_blocks;
		for (;;) {
			uint64_t gap_pkts;
			uint64_t ack_pkts;

			if (blocks_left) {
				uint64_t gap, ack;
				q_decode_varint(s, &gap);
				q_decode_varint(s, &ack);
				gap_pkts = gap + 1;
				ack_pkts = ack + 1;
				blocks_left--;
			} else if (num > b->tx_oldest) {
				gap_pkts = num - b->tx_oldest;
				ack_pkts = 0;
			} else {
				break;
			}

			do {
				qtx_packet_t *pkt = &b->sent[(--num) % b->sent_len];
				if (num < b->tx_oldest) {
					break;
				} else if (pkt->off == UINT64_MAX) {
					continue;
				} else if (num + 3 > largest && (tickdiff_t)(lost_threshold - pkt->sent) > 0) {
					continue;
				}
				if (!have_cwnd_lost && (pkt->flags & QPKT_CWND)) {
					have_cwnd_lost = true;
					q_cwnd_largest_lost(c, num);
				}
				lost_packet(c, pkt);
				if (num == b->tx_oldest) {
					update_oldest_packet(b);
					break;
				}
			} while (--gap_pkts);

			num -= ack_pkts;
		}

		q_reset_rx_timer(c, rxtime);
	}

	// Then ECN
	if (hdr & ACK_ECN_FLAG) {
		uint64_t ect0, ect1, ce;
		if (q_decode_varint(s, &ect0)
			|| q_decode_varint(s, &ect1)
			|| q_decode_varint(s, &ce)) {
			return QC_ERR_FRAME_ENCODING;
		}
		q_cwnd_ecn(c, largest, ce);
	}

	if ((c->flags & (QC_CLOSING|QC_HS_COMPLETE)) == QC_HS_COMPLETE && !before && q_cwnd_allow(c)) {
		q_async_send_data(c);
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

static int decrypt_packet(uint64_t base, const qcipher_class **k, uint8_t *pkt_begin, qslice_t *s, uint64_t *pktnum) {
	// copy the encoded packet number data out so that if it is less
	// than 4 bytes, we can copy it back after
	uint8_t tmp[4];
	memcpy(tmp, s->p, 4);
	(*k)->protect(k, s->p, 4, s->e - s->p);
	uint8_t *begin = s->p;
	s->p = q_decode_packet_number(s->p, base, pktnum);
	memcpy(s->p, tmp + (s->p - begin), 4 - (s->p - begin));
	s->e -= QUIC_TAG_SIZE;
	return s->p > s->e || (*k)->decrypt(k, *pktnum, pkt_begin, (size_t)(s->p - pkt_begin), s->p, s->e);
}

static int process_packet(struct connection *c, const qcipher_class **key, qpacket_buffer_t *b, enum qcrypto_level level, uint8_t *pkt_begin, qslice_t s, const struct sockaddr *sa, socklen_t salen, tick_t rxtime) {
	uint64_t pktnum;
	if (decrypt_packet(b->rx_next, key, pkt_begin, &s, &pktnum)) {
		return 0;
	}
	if (level == QC_HANDSHAKE) {
		c->flags |= QC_HS_RECEIVED;
	}
	int err = q_update_address(c, pktnum, sa, salen, rxtime);
	while (!err && s.p < s.e) {
		uint8_t hdr = *(s.p++);
		if (!(c->flags & QC_HS_COMPLETE)) {
			switch (hdr) {
			default:
				err = QC_ERR_DROP;
				break;
			case PADDING:
				s.p = find_non_padding(s.p, s.e);
				continue;
			case CONNECTION_CLOSE:
			case APPLICATION_CLOSE:
				err = q_decode_close(c, hdr, &s, rxtime);
				continue;
			case ACK | ACK_ECN_FLAG:
			case ACK:
				err = decode_ack(c, b, hdr, &s, rxtime);
				continue;
			case CRYPTO:
				err = q_decode_handshake_crypto(c, level, &s, rxtime);
				continue;
			}
		} else if ((hdr & STREAM_MASK) == STREAM) {
			q_async_ack(c, rxtime);
			err = q_decode_stream(c, hdr, &s);
		} else {
			switch (hdr) {
			default:
				err = QC_ERR_FRAME_ENCODING;
				break;
			case PADDING:
				s.p = find_non_padding(s.p, s.e);
				continue;
			case RST_STREAM:
				q_async_ack(c, rxtime);
				err = q_decode_reset(c, &s);
				continue;
			case CONNECTION_CLOSE:
			case APPLICATION_CLOSE:
				err = q_decode_close(c, hdr, &s, rxtime);
				continue;
			case MAX_DATA:
				q_async_ack(c, rxtime);
				err = q_decode_max_data(c, &s);
				continue;
			case MAX_STREAM_DATA:
				q_async_ack(c, rxtime);
				err = q_decode_stream_data(c, &s);
				continue;
			case MAX_STREAM_ID:
				q_async_ack(c, rxtime);
				err = q_decode_max_id(c, &s);
				continue;
			case PING:
				q_fast_async_ack(c, rxtime);
				continue;
			case BLOCKED:
				err = q_decode_blocked(c, &s);
				continue;
			case STREAM_BLOCKED:
				err = q_decode_stream_blocked(c, &s);
				continue;
			case STREAM_ID_BLOCKED:
				err = q_decode_id_blocked(c, &s);
				continue;
			case NEW_CONNECTION_ID:
				q_async_ack(c, rxtime);
				err = q_decode_new_id(c, &s);
				continue;
			case RETIRE_CONNECTION_ID:
				q_async_ack(c, rxtime);
				err = q_decode_retire_id(c, &s);
				continue;
			case STOP_SENDING:
				q_async_ack(c, rxtime);
				err = q_decode_stop(c, &s);
				continue;
			case ACK | ACK_ECN_FLAG:
			case ACK:
				err = decode_ack(c, &c->prot_pkts, hdr, &s, rxtime);
				continue;
			case PATH_CHALLENGE:
				q_async_ack(c, rxtime);
				err = q_decode_path_challenge(c, &s);
				continue;
			case PATH_RESPONSE:
				q_async_ack(c, rxtime);
				err = q_decode_path_response(c, &s);
				continue;
			case NEW_TOKEN:
				q_async_ack(c, rxtime);
				err = q_decode_new_token(c, &s);
				continue;
			case CRYPTO:
				q_fast_async_ack(c, rxtime);
				err = q_decode_handshake_crypto(c, QC_PROTECTED, &s, rxtime);
				continue;
			}
		}
	}
	if (err != QC_ERR_DROP) {
		receive_packet(c, b, pktnum, rxtime);
		if (err) {
			q_shutdown_from_library(c, err);
			return -1;
		}
	}
	return 0;
}

uint64_t qc_get_destination(void *buf, size_t len) {
	// This does not support an ID of 8 0s. Oh well.
	// This should only rely on the invariants as we don't check the version yet
	uint8_t *u = buf;
	if (len < 1 + DEFAULT_SERVER_ID_LEN) {
		return 0;
	}
	if (*(u++) & LONG_HEADER_FLAG) {
		u += 4; // skip over version
		uint8_t dcil = q_decode_id_len(*(u++) >> 4);
		if (dcil != DEFAULT_SERVER_ID_LEN || len < 6 + DEFAULT_SERVER_ID_LEN) {
			return 0;
		}
	}
	return little_64(u);
}

int qc_decode_request(qconnect_request_t *req, const qconnection_cfg_t *cfg, void *buf, size_t buflen, const struct sockaddr *sa, socklen_t salen, tick_t rxtime) {
	assert(sa != NULL);
	memset(req, 0, sizeof(*req));
	req->sa = sa;
	req->salen = salen;
	req->rxtime = rxtime;
	req->server_cfg = cfg;

	qslice_t s;
	s.p = (uint8_t*)buf;
	s.e = s.p + buflen;
	if (s.p + 6 > s.e || *(s.p++) != INITIAL_PACKET) {
		return QC_PARSE_ERROR;
	}
	uint32_t version = big_32(s.p);
	s.p += 4;
	req->server_len = q_decode_id_len(*s.p >> 4);
	req->client_len = q_decode_id_len(*s.p & 0xF);
	s.p++;
	if (s.p + req->server_len + req->client_len > s.e) {
		return QC_PARSE_ERROR;
	}

	req->server = s.p;
	s.p += req->server_len;

	req->client = s.p;
	s.p += req->client_len;

	// check version, up to this point we must only depend on the QUIC invariants
	if (version != QUIC_VERSION) {
		return QC_WRONG_VERSION;
	}
	req->version = version;

	// Note this must be done after the version check as the
	// default ID length may vary with the version.
	if (req->server_len != DEFAULT_SERVER_ID_LEN || little_64(req->server) == 0) {
		return QC_PARSE_ERROR;
	}

	// token
	uint64_t toksz;
	if (q_decode_varint(&s, &toksz) || toksz > (uint64_t)(s.e - s.p)) {
		return QC_PARSE_ERROR;
	} else if (cfg->validate_path && !q_is_retry_valid(req, s.p, (size_t)toksz)) {
		return QC_STATELESS_RETRY;
	}
	s.p += toksz;

	// length
	uint64_t paysz;
	if (q_decode_varint(&s, &paysz) || paysz > (uint64_t)(s.e - s.p)) {
		return QC_PARSE_ERROR;
	}
	s.e = s.p + paysz;

	// decrypt
	qcipher_aes_gcm key;
	init_initial_cipher(&key, STREAM_CLIENT, req->server, DEFAULT_SERVER_ID_LEN);
	if (decrypt_packet(0, &key.vtable, (uint8_t*)buf, &s, &req->pktnum)) {
		return QC_PARSE_ERROR;
	}

	while (s.p < s.e) {
		switch (*(s.p++)) {
		default:
			return QC_PARSE_ERROR;
		case PADDING:
			s.p = find_non_padding(s.p, s.e);
			break;
		case CRYPTO: {
			if (q_decode_request_crypto(req, &s)) {
				return QC_PARSE_ERROR;
			}
			break;
		}
		}
	}

	if (!req->chello) {
		return QC_PARSE_ERROR;
	}
	return 0;
}

size_t qc_reject(qconnect_request_t *req, int err, void *buf, size_t bufsz) {
	switch (err) {
	case QC_WRONG_VERSION:
		return q_encode_version(req, buf, bufsz);
	case QC_STATELESS_RETRY:
		return q_encode_retry(req, buf, bufsz);
	default:
		return 0;
	}
}


void qc_recv(qconnection_t *cin, void *buf, size_t len, const struct sockaddr *sa, socklen_t salen, tick_t rxtime) {
	struct connection *c = (struct connection*)cin;
	struct handshake *h = (struct handshake*)c;
	struct client_handshake *ch = (struct client_handshake*)c;
	struct server_handshake *sh = (struct server_handshake*)c;
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
			// skip over ids
			uint8_t dcil = q_decode_id_len(*s.p >> 4);
			uint8_t scil = q_decode_id_len(*s.p & 0xF);
			s.p++;
			s.p += dcil;
			const uint8_t *source = s.p;
			s.p += scil;
			if (s.p > s.e) {
				return;
			}

			// check the version
			if ((c->flags & (QC_IS_SERVER | QC_HS_COMPLETE)) == 0 && !ch->initial_version && !version) {
				q_process_version(ch, s, rxtime);
				return;
			} else if (version != QUIC_VERSION) {
				return;
			}

			switch (hdr) {
			case INITIAL_PACKET: {
				uint64_t toksz;
				if (q_decode_varint(&s, &toksz) || toksz > (uint64_t)(s.e - s.p)) {
					return;
				}
				s.p += (size_t)toksz;
				break;
			}
			case HANDSHAKE_PACKET:
			case PROTECTED_PACKET:
				break;
			case RETRY_PACKET:
				if ((c->flags & (QC_IS_SERVER | QC_HS_COMPLETE)) == 0 && !h->orig_server_id) {
					q_process_retry(ch, scil, source, s, rxtime);
				}
				return;
			default:
				return;
			}

			uint64_t paysz;
			if (q_decode_varint(&s, &paysz) || paysz > (uint64_t)(s.e - s.p) || paysz < QUIC_TAG_SIZE + 1) {
				return;
			}
			qslice_t pkt = { s.p, s.p + (size_t)paysz };
			s.p = pkt.e;

			enum qcrypto_level level;
			qcipher_compat key;

			if (c->flags & QC_HS_COMPLETE) {
				continue;
			} else if (hdr == INITIAL_PACKET) {
				if (c->flags & QC_IS_SERVER) {
					init_initial_cipher(&key.aes_gcm, STREAM_CLIENT, sh->server_id, DEFAULT_SERVER_ID_LEN);
				} else {
					init_initial_cipher(&key.aes_gcm, STREAM_SERVER, c->peer_id, c->peer_len);
				}
				level = QC_INITIAL;
			} else if (hdr == HANDSHAKE_PACKET && (c->flags & QC_INIT_COMPLETE)) {
				c->prot_rx.vtable->init(&key.vtable, h->hs_rx);
				level = QC_HANDSHAKE;
			} else {
				continue;
			}

			if (process_packet(c, &key.vtable, &h->pkts[level], level, pkt_begin, pkt, sa, salen, rxtime)) {
				return;
			}

		} else if ((hdr & SHORT_PACKET_MASK) == SHORT_PACKET) {
			// short header
			s.p += (c->flags & QC_IS_SERVER) ? DEFAULT_SERVER_ID_LEN : 0;
			if (s.p + 1 + QUIC_TAG_SIZE <= s.e && c->prot_rx.vtable) {
				process_packet(c, &c->prot_rx.vtable, &c->prot_pkts, QC_PROTECTED, pkt_begin, s, sa, salen, rxtime);
			}
			return;
		}
	}
}




//////////////////////////////
// Initialization

static void init_connection(struct handshake *h, size_t csz) {
	h->c.peer_cfg.ack_delay_exponent = QUIC_ACK_DELAY_SHIFT;
	h->conn_buf_end = (uint8_t*)h + csz;
	h->c.next_id[0] = 0;
	h->c.next_id[1] = 1;
	h->c.next_id[2] = 2;
	h->c.next_id[3] = 3;
	q_reset_cwnd(&h->c, 0);
}

int qc_connect(qconnection_t *cin, size_t csz, dispatcher_t *d, const qinterface_t **vt, const qconnection_cfg_t *cfg, const char *server_name, const br_x509_class **x) {
	struct connection *c = (struct connection*)cin;
	struct handshake *h = (struct handshake*)cin;
	struct client_handshake *ch = (struct client_handshake*)cin;
	br_hmac_drbg_context rand;
	if (csz < sizeof(*ch) + BR_EC_KBUF_PRIV_MAX_SIZE || seed_rand(&rand, cfg)) {
		return -1;
	}
	memset(ch, 0, sizeof(*ch));
	init_connection(h, csz);
	c->version = cfg->versions ? cfg->versions[0] : QUIC_VERSION;
	c->flags = 0;
	c->iface = vt;
	c->local_cfg = cfg;
	c->dispatcher = d;
	ch->server_name = server_name;
	ch->x509 = x;
	h->crypto.level = QC_INITIAL;
	h->crypto.state = CLIENT_START;
	h->crypto.end = UINT32_MAX;
	h->pkts[QC_INITIAL].sent = ch->init_pkts;
	h->pkts[QC_INITIAL].sent_len = ARRAYSZ(ch->init_pkts);
	h->pkts[QC_HANDSHAKE].sent = ch->hs_pkts;
	h->pkts[QC_HANDSHAKE].sent_len = ARRAYSZ(ch->hs_pkts);

	c->peer_len = DEFAULT_SERVER_ID_LEN;
	br_hmac_drbg_generate(&rand, c->peer_id, DEFAULT_SERVER_ID_LEN);
	if (little_64(c->peer_id) == 0) {
		return -1;
	}


	// generate a private key for the high priority groups
	const br_ec_impl *ec = br_ec_get_default();
	size_t n = 0;
	while (cfg->groups[n] != 0 && &ch->keys[(n+1) * BR_EC_KBUF_PRIV_MAX_SIZE] <= h->conn_buf_end) {
		if (!br_ec_keygen(&rand.vtable, ec, NULL, &ch->keys[n * BR_EC_KBUF_PRIV_MAX_SIZE], cfg->groups[n])) {
			return -1;
		}
		n++;
	}
	ch->key_num = n;

	qtx_packet_t *pkt = q_send_client_hello(ch, &rand.vtable, 0);
	if (!pkt) {
		return -1;
	}
	q_start_handshake_timers(h, pkt->sent);
	return 0;
}

int qc_accept(qconnection_t *cin, size_t csz, dispatcher_t *d, const qinterface_t **vt, const qconnect_request_t *req, const qsigner_class *const *signer) {
	struct connection *c = (struct connection*)cin;
	struct handshake *h = (struct handshake*)cin;
	struct server_handshake *sh = (struct server_handshake*)cin;
	br_hmac_drbg_context rand;
	if (csz < sizeof(*sh) || seed_rand(&rand, req->server_cfg)) {
		return -1;
	}
	memset(sh, 0, sizeof(*sh));
	init_connection(h, csz);
	c->version = req->version;
	c->flags = QC_IS_SERVER | QC_INIT_COMPLETE;
	c->iface = vt;
	c->local_cfg = req->server_cfg;
	c->peer_cfg = req->client_cfg;
	c->dispatcher = d;
	sh->signer = signer;
	h->orig_server_id = req->orig_server_id;
	c->peer_len = req->client_len;
	memcpy(sh->server_id, req->server, DEFAULT_SERVER_ID_LEN);
	memcpy(c->peer_id, req->client, req->client_len);
	memcpy(c->client_random, req->client_random, QUIC_RANDOM_SIZE);
	memcpy(&c->addr, req->sa, req->salen);
	c->addr_len = req->salen;
	h->crypto.level = QC_PROTECTED;
	h->crypto.state = ACCEPT_START;
	h->crypto.end = UINT32_MAX;
	h->pkts[QC_INITIAL].sent = sh->init_pkts;
	h->pkts[QC_INITIAL].sent_len = ARRAYSZ(sh->init_pkts);
	h->pkts[QC_HANDSHAKE].sent = sh->hs_pkts;
	h->pkts[QC_HANDSHAKE].sent_len = ARRAYSZ(sh->hs_pkts);

	// key group
	if (!req->key.curve || !br_ec_keygen(&rand.vtable, br_ec_get_default(), &sh->sk, sh->key_data, req->key.curve)) {
		return -1;
	}

	// certificates
	sh->signature = choose_signature(signer, req->signatures);
	if (!sh->signature) {
		return -1;
	}

	// cipher & transcript
	if (!req->cipher) {
		return -1;
	}
	c->prot_rx.vtable = req->cipher;
	c->prot_tx.vtable = req->cipher;
	const br_hash_class **msgs = init_message_hash(h);
	(*msgs)->init(msgs);
	(*msgs)->update(msgs, req->chello, req->chello_size);

	// send server hello
	receive_packet(c, &h->pkts[QC_INITIAL], req->pktnum, req->rxtime);
	if (q_send_server_hello(sh, &rand.vtable, &req->key, req->rxtime)) {
		return -1;
	}

	q_start_handshake_timers(h, req->rxtime);
	return 0;
}

