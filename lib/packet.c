#include "internal.h"

//////////////////////////
// Ack Generation

void q_receive_packet(struct connection *c, enum qcrypto_level level, uint64_t num, tick_t rxtime) {
	qpacket_buffer_t *s = (level == QC_PROTECTED) ? &c->prot_pkts : &((struct handshake*)c)->pkts[level];
	assert(level == QC_PROTECTED || !c->peer_verified);
	if (level == QC_PROTECTED && !c->handshake_complete) {
		// Until this point, the client will send the finished message in every
		// protected packet. Once the server has acknowledged one, we know that it
		// got the finished frame and the handshake is complete.
		LOG(c->local_cfg->debug, "client handshake complete");
		c->handshake_complete = true;
	}
	if (level == QC_PROTECTED && num > s->rx_next) {
		// out of order or dropped packet
		q_fast_async_ack(c, rxtime);
	}
	if (num >= s->rx_next) {
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
		size_t shift = (size_t)(s->rx_next - ALIGN_DOWN(uint64_t, s->rx_next, 64));
		uint64_t mask = UINT64_C(1) << (num - s->rx_next);
		mask -= 1; // create a mask of n bits
		mask = (mask << shift) | (mask >> (64 - shift)); // and rotate left
		s->rx_mask &= ~mask; // and turn off the new bits
		s->rx_next = num + 1;
	}

	s->rx_mask |= UINT64_C(1) << (num & 63);
}

// clzl = count leading zeros (long)
// These versions do not protect against a zero value
#if defined __GNUC__
static unsigned clzl(uint64_t v) {
#if defined __amd64__
	return __builtin_clzl(v);
#else
	uint32_t lo = (uint32_t)v;
	uint32_t hi = (uint32_t)(v >> 32);
	return hi ? __builtin_clz(hi) : (32 + __builtin_clz(lo));
#endif
}
#elif defined _MSC_VER
#include <intrin.h>
#if defined _M_X64
#pragma intrinsic(_BitScanReverse64)
static unsigned clzl(uint64_t v) {
	unsigned long ret;
	_BitScanReverse64(&ret, v);
	return 63 - ret;
}
#else
#pragma intrinsic(_BitScanReverse)
static unsigned clzl(uint64_t v) {
	unsigned long ret;
	if (_BitScanReverse(&ret, (uint32_t)(v >> 32))) {
		return 31 - ret;
	} else {
		_BitScanReverse(&ret, (uint32_t)(v));
		return 63 - ret;
	}
}
#endif
#else
static unsigned clzl(uint64_t v) {
	unsigned n = 0;
	int64_t x = (int64_t)v;
	while (!(x < 0)) {
		n++;
		x <<= 1;
	}
	return n;
}
#endif


static int encode_ack_frame(qslice_t *s, qpacket_buffer_t *pkts, tickdiff_t delay, unsigned exp) {
	static const unsigned max_blocks = 16;
	size_t ack_size = 1 + 8 + 8 + 1 + 1 + 2 * max_blocks;
	if (s->p + ack_size > s->e) {
		return -1;
	} else if (!pkts->rx_next) {
		return 0;
	}

	*(s->p++) = ACK;

	// largest acknowledged
	s->p = encode_varint(s->p, pkts->rx_next - 1);

	// ack delay
	s->p = encode_varint(s->p, q_encode_ack_delay(delay, exp));

	// block count - fill out later
	uint8_t *pblock_count = s->p++;
	unsigned num_blocks = 0;

	// rotate left such that the latest (b.next-1) packet is in the top bit
	unsigned shift = (unsigned)(ALIGN_UP(uint64_t, pkts->rx_next, 64) - pkts->rx_next);
	uint64_t rx = (pkts->rx_mask << shift) | (pkts->rx_mask >> (64 - shift));

	// and shift the latest packet out
	rx <<= 1;

	// find the first block
	// rx is not all ones due to the shift above. Thus clz(~rx) is not called with a 0 value.
	unsigned first_block = clzl(~rx);
	*(s->p++) = (uint8_t)first_block;
	rx <<= first_block;

	while (rx && num_blocks < max_blocks) {
		// there is at least one 1 bit in rx
		// clz(rx) will return the number of 0s at the top (ie the gap)
		// clz(~(rx << gap)) will return the length of 1s section (ie the block)

		// find the gap
		unsigned gap = clzl(rx);
		*(s->p++) = (uint8_t)gap;
		rx <<= gap;

		// find the block
		unsigned block = clzl(~rx);
		*(s->p++) = (uint8_t)block;
		rx <<= block;

		num_blocks++;
	}

	*pblock_count = (uint8_t)num_blocks;
	return 0;
}

qtx_packet_t *q_encode_long_packet(struct handshake *h, qslice_t *s, struct long_packet *p, tick_t now) {
	struct connection *c = &h->c;
	assert(!c->peer_verified);
	assert(p->level <= QC_HANDSHAKE);
	qpacket_buffer_t *pkts = &h->pkts[p->level];
	if (c->closing) {
		return NULL;
	} else if (pkts->tx_next >= pkts->tx_oldest + pkts->sent_len) {
		// we've run out of room in the transmit packet buffer
		// need to wait for some packets to be ack'ed or lost
		return NULL;
	} else if (s->p + 1 + 4 + 2 * QUIC_ADDRESS_SIZE + 1 + 2 + 4 + QUIC_TAG_SIZE > s->e) {
		return NULL;
	}

	qtx_packet_t *pkt = &pkts->sent[pkts->tx_next % pkts->sent_len];
	memset(pkt, 0, sizeof(*pkt));

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
	if (encode_ack_frame(s, pkts, (tickdiff_t)(now - pkts->rx_largest), 0)) {
		return NULL;
	}
	pkt->flags |= QPKT_ACK;

	// crypto frame
	if (p->crypto_size) {
		size_t chdr = 1 + 4 + 4;
		if (s->p + chdr + QUIC_TAG_SIZE > s->e) {
			return NULL;
		}
		size_t sz = MIN(p->crypto_size, (size_t)(s->e - s->p) - chdr);
		*(s->p++) = CRYPTO;
		s->p = encode_varint(s->p, p->crypto_off);
		s->p = encode_varint(s->p, sz);
		s->p = append(s->p, p->crypto_data, sz);
		pkt->flags |= QPKT_CRYPTO;
		pkt->off = p->crypto_off;
		pkt->len = (uint16_t)sz;
		p->crypto_off += sz;
		p->crypto_data += sz;
		p->crypto_size -= sz;
	}

	// padding
	if (p->pad) {
		size_t pad = (size_t)(s->e - s->p) - QUIC_TAG_SIZE;
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
	return pkt;
}

int q_send_short_packet(struct connection *c, struct short_packet *s, tick_t *pnow) {
	qpacket_buffer_t *pkts = &c->prot_pkts;
	if (!c->peer_verified || (!s->ignore_closing && c->closing) || (!s->ignore_draining && c->draining)) {
		return -1;
	} else if (pkts->tx_next == pkts->tx_oldest + pkts->sent_len) {
		return -1;
	}

	bool include_client_finished = !c->handshake_complete;
	qtx_packet_t *pkt = &pkts->sent[pkts->tx_next % pkts->sent_len];
	memset(pkt, 0, sizeof(*pkt));

	uint8_t buf[DEFAULT_PACKET_SIZE];
	qslice_t p = { buf, buf + sizeof(buf) };

	if (p.p + 1 + c->peer_id[0] + QUIC_TAG_SIZE > p.e) {
		return -1;
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
	p.e -= QUIC_TAG_SIZE;

	// ack
	if (pnow && s->send_ack) {
		if (encode_ack_frame(&p, pkts, (tickdiff_t)(*pnow - pkts->rx_largest), c->local_cfg->ack_delay_exponent)) {
			return -1;
		}
		pkt->flags |= QPKT_ACK;
	}

	if (!s->ignore_cwnd) {
		size_t winsz = q_cwnd_allowed_bytes(c);
		if (p.p + winsz < p.e) {
			p.e = p.p + winsz;
		}
	}

	// max data & id
	// These decide for themselves whether to include data.
	if (q_encode_scheduler(c, &p, pkt)) {
		return -1;
	}

	// client finished
	if (include_client_finished) {
		if (p.p + 1 + 1 + 2 > p.e) {
			return -1;
		}
		*(p.p++) = CRYPTO;
		*(p.p++) = 0; // offset
		p.p += 2; // length
		uint8_t *fin_start = p.p;
		int err = encode_finished(&p, c->prot_tx.vtable->hash, c->tx_finished);
		if (err) {
			return err;
		}
		write_big_16(fin_start - 2, VARINT_16 | (uint16_t)(p.p - fin_start));
	}

	if (s->send_close) {
		assert(!s->stream);
		if (q_encode_close(c, &p, pkt)) {
			return -1;
		}
	} else if (s->stream) {
		if (q_encode_stream(c, &p, s->stream, &s->stream_off, pkt)) {
			return -1;
		}
	} else if (s->force_ack) {
		// this is a forced packet
		// add a ping to force the other side to respond
		if (p.p == p.e) {
			return -1;
		}
		*(p.p++) = PING;
		LOG(c->local_cfg->debug, "TX PING");

	} else {
		LOG(c->local_cfg->debug, "TX ACK");
	}

	if (p.p > p.e) {
		return -1;
	}

	// As the server has not yet verified our address, we need to pad out the packet
	if (include_client_finished) {
		size_t pad = (size_t)(p.e - p.p);
		memset(p.p, PADDING, pad);
		p.p += pad;
	}

	// tag
	uint8_t *tag = p.p;
	p.p += QUIC_TAG_SIZE;
	p.e += QUIC_TAG_SIZE;

	const qcipher_class **k = &c->prot_tx.vtable;
	(*k)->encrypt(k, pkts->tx_next, pkt_begin, enc_begin, tag);
	(*k)->protect(k, packet_number, (size_t)(enc_begin - packet_number), (size_t)(p.p - packet_number));

	int err = (*c->iface)->send(c->iface, buf, (size_t)(p.p - buf), NULL, 0, &pkt->sent);
	if (err) {
		return err;
	}
	if (pkt->flags & QPKT_RETRANSMIT) {
		c->retransmit_packets++;
		q_start_probe_timer(c, pkt->sent);
	}
	if (pkt->flags & QPKT_ACK) {
		cancel_apc(c->dispatcher, &c->tx_timer);
	}
	if (s->stream) {
		q_commit_stream(c, s->stream, pkt);
	}
	q_commit_scheduler(c, pkt);
	q_cwnd_sent(c, pkt);
	pkts->tx_next++;
	if (pnow) {
		*pnow = pkt->sent;
	}
	return 0;
}

