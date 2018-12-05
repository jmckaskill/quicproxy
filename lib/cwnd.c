#include "internal.h"

bool q_cwnd_allow(struct connection *c) {
	return c->bytes_in_flight + DEFAULT_PACKET_SIZE / 2 < c->congestion_window;
}

// After a RTO timeout or path change, we reset the congestion window.
// In this mode, we keep the bytes_in_flight valid, but otherwise
// restart the congestion mechanism. Slow start will continue
// as from a new connection once we get packets past the reset point.
void q_reset_cwnd(struct connection *c, uint64_t first_after_reset) {
	c->congestion_window = INITIAL_WINDOW;
	c->after_recovery = first_after_reset;
	c->slow_start_threshold = UINT64_MAX;
	c->min_rtt = INT32_MAX;
	c->srtt = 0;
	c->rttvar = 0;
}

// This function must not use any data outside of the packet as
// the connection state may have changed between the sending and ack/lost
// In order for counting to be accurate it must return the same value
// at each stage.
static size_t packet_bytes(const qtx_packet_t *pkt) {
	size_t ret = 0;
	unsigned flags = pkt->flags;
	if (flags & QPKT_MAX_DATA) {
		ret += 1 + 4;
	}
	if (flags & QPKT_MAX_ID_BIDI) {
		ret += 1 + 4;
	}
	if (flags & QPKT_MAX_ID_UNI) {
		ret += 1 + 4;
	}
	if (flags & QPKT_PATH_CHALLENGE) {
		ret += 9;
	}
	if (flags & QPKT_PATH_RESPONSE) {
		ret += 9;
	}
	if (flags & QPKT_STREAM_DATA) {
		ret += 1 + 4 + 4;
	}
	if (flags & QPKT_STOP) {
		ret += 1 + 2;
	}
	if (flags & QS_TX_RST) {
		ret += 1 + 2 + 4;
	}
	if (pkt->len || (flags & QS_TX_FIN)) {
		ret += 1 + 4 + 4 + 2 + pkt->len;
	}
	if (!ret) {
		return 0;
	}
	// rough ballpark average as we don't keep track of the actual size
	return ret + 15 + QUIC_TAG_SIZE;
}

static bool in_recovery(struct connection *c, uint64_t pktnum) {
	return pktnum < c->after_recovery;
}

size_t q_cwnd_sent(struct connection *c, const qtx_packet_t *pkt) {
	size_t bytes = packet_bytes(pkt);
	c->bytes_in_flight += bytes;
	return bytes;
}

void q_ack_cwnd(struct connection *c, uint64_t pktnum, const qtx_packet_t *pkt) {
	size_t bytes = packet_bytes(pkt);
	c->bytes_in_flight -= bytes;
	if (in_recovery(c, pktnum)) {
		// Recovery
	} else if (c->congestion_window < c->slow_start_threshold) {
		// Slow Start
		c->congestion_window += bytes;
	} else {
		// Congestion Avoidance
		c->congestion_window += (DEFAULT_PACKET_SIZE * bytes) / c->congestion_window;
	}
}

static void congestion_event(struct connection *c, uint64_t pktnum) {
	if (!in_recovery(c, pktnum)) {
		c->after_recovery = c->prot_pkts.tx_next;
		c->congestion_window = MAX(c->congestion_window / 2, MIN_WINDOW);
		c->slow_start_threshold = c->congestion_window;
	}
}

void q_cwnd_ecn(struct connection *c, uint64_t pktnum, uint64_t ecn_ce) {
	if (ecn_ce > c->ecn_ce_counter) {
		c->ecn_ce_counter = ecn_ce;
		congestion_event(c, pktnum);
	}
}

void q_lost_cwnd(struct connection *c, const qtx_packet_t *pkt) {
	c->bytes_in_flight -= packet_bytes(pkt);
}

void q_cwnd_largest_lost(struct connection *c, uint64_t pktnum) {
	congestion_event(c, pktnum);
}

