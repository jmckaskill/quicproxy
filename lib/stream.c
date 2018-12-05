#include "internal.h"
#include <inttypes.h>

void qinit_stream(qstream_t *s, void *txbuf, size_t txlen, void *rxbuf, size_t rxlen) {
	memset(s, 0, sizeof(*s));
	qbuf_init(&s->rx, rxbuf, rxlen); 
	qbuf_init(&s->tx, txbuf, txlen);
	s->id = UINT64_MAX;
}

void q_setup_remote_stream(struct connection *c, qstream_t *s, uint64_t id) {
	bool uni = (id & STREAM_UNI_MASK) == STREAM_UNI;
	if (uni) {
		qbuf_init(&s->tx, NULL, 0);
		s->flags &= ~QS_TX_RST_SEND;
		s->flags |= QS_TX_COMPLETE | QS_TX_RST | QS_RX_RST_ACK;
		s->tx_max_allowed = 0;
		s->rx_max_allowed = c->local_cfg->stream_data_uni;
	} else {
		s->tx_max_allowed = c->peer_cfg.stream_data_bidi_local;
		s->rx_max_allowed = c->local_cfg->stream_data_bidi_remote;
	}
	assert(qbuf_max(&s->rx) >= s->rx_max_allowed);
	s->id = id;
	s->flags |= QS_STARTED | QS_TX_CONTROL;
}

void q_setup_local_stream(struct connection *c, qstream_t *s, uint64_t id) {
	bool uni = (s->rx.size == 0);
	if (uni) {
		qbuf_init(&s->rx, NULL, 0);
		s->flags &= ~QS_TX_STOP_SEND;
		s->flags |= QS_RX_COMPLETE | QS_TX_STOP | QS_RX_STOP_ACK;
		s->tx_max_allowed = c->peer_cfg.stream_data_uni;
		s->rx_max_allowed = 0;
	} else {
		s->flags |= QS_TX_CONTROL;
		s->tx_max_allowed = c->peer_cfg.stream_data_bidi_remote;
		s->rx_max_allowed = c->local_cfg->stream_data_bidi_local;
	}
	assert(qbuf_max(&s->rx) >= s->rx_max_allowed);
	s->flags |= QS_NOT_STARTED | QS_TX_CONTROL;
	s->id = id;
}

bool qrx_eof(qstream_t *s) {
	return (s->flags & QS_RX_FIN) && s->rx.head == s->rx_max_received;
}

bool qrx_error(qstream_t *s) {
	return (s->flags | QS_RX_RST) != 0;
}

void qrx_stop(qstream_t *s, int errnum) {
	if (!(s->flags & QS_TX_STOP)) {
		s->flags |= QS_TX_STOP | QS_TX_STOP_SEND | QS_TX_CONTROL | QS_RX_COMPLETE;
		s->stop_errnum = errnum;
		qbuf_init(&s->rx, NULL, 0);
	}
}

size_t qrx_read(qstream_t *s, void *data, size_t len) {
	if (s->flags & (QS_TX_STOP | QS_RX_RST)) {
		return 0;
	} else {
		uint64_t off = s->rx.head;
		len = qbuf_copy(&s->rx, off, data, len);
		qbuf_consume(&s->rx, len);
		return len;
	}
}

void qtx_cancel(qstream_t *s, int errnum) {
	if (!(s->flags & QS_TX_RST)) {
		s->rst_errnum = errnum;
		s->flags |= QS_TX_RST | QS_TX_RST_SEND | QS_TX_CONTROL;
		qbuf_init(&s->tx, NULL, 0);
	}
}

void qtx_finish(qstream_t *s) {
	if (!(s->flags & QS_TX_FIN)) {
		s->flags |= QS_TX_FIN | QS_TX_FIN_SEND | QS_TX_CONTROL;
	}
}

size_t qtx_write(qstream_t *s, const void *data, size_t len) {
	uint64_t end = MIN(s->tx.tail + len, qtx_max(s));
	len = (size_t)(end - s->tx.tail);
	qbuf_insert(&s->tx, s->tx.tail, data, len);
	qbuf_fold(&s->tx);
	return len;
}

static void remove_stream_if_complete(struct connection *c, qstream_t *s) {
	assert(s->id >= 0);
	if ((s->flags & QS_RX_COMPLETE) && (s->flags & QS_TX_COMPLETE)) {
		q_remove_stream(c, s);
	}
}

static int update_recv_flow(struct connection *c, qstream_t *s, uint64_t end) {
	assert(end <= qbuf_max(&s->rx));
	if (end > s->rx_max_allowed) {
		return -1;
	}
	if (end > s->rx_max_received) {
		uint64_t new_data = end - s->rx_max_received;
		if (c->rx_data + new_data > c->rx_data_max) {
			return -1;
		}
		c->rx_data += new_data;
		s->rx_max_received = end;
		// Don't kick off a send data per se. Instead rely on the ack timer or
		// already planned data being sent to update max data.
	}
	return 0;
}

int q_recv_stream(struct connection *c, qstream_t *s, bool fin, uint64_t off, const void *p, size_t sz) {
	uint64_t end = off + sz;
	if (update_recv_flow(c, s, end)) {
		return QC_ERR_FLOW_CONTROL;
	} else if ((s->flags & (QS_RX_RST | QS_RX_FIN)) && end > s->rx_max_received) {
		return QC_ERR_FINAL_OFFSET;
	} else if (s->flags & (QS_TX_STOP | QS_RX_RST | QS_RX_COMPLETE)) {
		return 0;
	}

	if (fin) {
		if ((s->flags & QS_RX_FIN) && end != s->rx_max_received) {
			return QC_ERR_FINAL_OFFSET;
		}
		s->flags |= QS_RX_FIN;
	}

	if (qbuf_insert(&s->rx, off, p, sz)) {
		if ((s->flags & QS_RX_FIN) && s->rx.tail == s->rx_max_received) {
			s->flags |= QS_RX_COMPLETE;
		}

		if ((*c->iface)->data_received) {
			(*c->iface)->data_received(c->iface, s);
		}
	}
	qbuf_fold(&s->rx);

	remove_stream_if_complete(c, s);
	return 0;
}

int q_recv_max_stream(struct connection *c, qstream_t *s, uint64_t off) {
	if (off > s->tx_max_allowed) {
		s->tx_max_allowed = off;
		qc_flush((qconnection_t*)c, s);
	}
	return 0;
}

int q_recv_stop(struct connection *c, qstream_t *s, int errnum) {
	s->rx_errnum = errnum;
	s->flags |= QS_RX_STOP;
	qtx_cancel(s, QRST_STOPPING);
	qc_flush((qconnection_t*)c, s);
	return 0;
}

int q_recv_reset(struct connection *c, qstream_t *s, int errnum, uint64_t off) {
	if (s->rx_max_received > off) {
		// hang on, we've received data after the "final offset"
		return QC_ERR_PROTOCOL_VIOLATION;
	} else if (update_recv_flow(c, s, off)) {
		return QC_ERR_FLOW_CONTROL;
	} else if (s->flags & (QS_RX_RST | QS_RX_COMPLETE)) {
		return 0;
	}

	s->rx_errnum = errnum;
	s->flags &= ~(QS_RX_FIN | QS_TX_STOP_SEND);
	s->flags |= QS_RX_RST | QS_RX_COMPLETE | QS_TX_STOP | QS_RX_STOP_ACK;
	qbuf_init(&s->rx, NULL, 0);

	if ((*c->iface)->data_received) {
		(*c->iface)->data_received(c->iface, s);
	}
	remove_stream_if_complete(c, s);
	return 0;
}

static void insert_stream_packet(qstream_t *s, qtx_packet_t *pkt, uint64_t off) {
	rbnode *p = s->packets.root;
	rbdirection dir = RB_LEFT;
	while (p) {
		qtx_packet_t *pp = container_of(p, qtx_packet_t, rb);
		dir = (off < pp->off) ? RB_LEFT : RB_RIGHT;
		if (!rb_child(p, dir)) {
			break;
		}
		p = rb_child(p, dir);
	}
	rb_insert(&s->packets, p, &pkt->rb, dir);
}

uint8_t *q_encode_stream(struct connection *c, qstream_t *s, uint8_t *p, uint8_t *e, qtx_packet_t *pkt) {
	uint8_t *begin = p;

	uint64_t new_max = qbuf_max(&s->rx);
	if (new_max > s->rx_max_allowed && !(s->flags & QS_TX_STOP)) {
		*(p++) = MAX_STREAM_DATA;
		p = encode_varint(p, s->id);
		p = encode_varint(p, new_max);
		pkt->flags |= QPKT_STREAM_DATA;
	}

	if (s->flags & QS_TX_STOP_SEND) {
		*(p++) = STOP_SENDING;
		p = encode_varint(p, s->id);
		p = write_big_16(p, (uint16_t)(s->stop_errnum - QC_ERR_APP_OFFSET));
		pkt->flags |= QPKT_STOP;
	}

	if (s->flags & QS_TX_RST_SEND) {
		*(p++) = RST_STREAM;
		p = encode_varint(p, s->id);
		p = write_big_16(p, (uint16_t)(s->rst_errnum - QC_ERR_APP_OFFSET));
		p = encode_varint(p, s->tx.tail);
		pkt->flags |= QPKT_RST;
	}

	uint64_t sflow = s->tx_max_allowed;
	uint64_t cflow = s->tx_max_sent + c->tx_data_max - c->tx_data;
	size_t flowsz = (size_t)(MIN(cflow, sflow) - s->tx_next);
	bool not_started = (s->flags & QS_NOT_STARTED);

	if (not_started || (s->flags & QS_TX_FIN_SEND) || (flowsz && s->tx_next < s->tx.tail)) {
		uint8_t *hdr = p;
		*p++ = STREAM;
		p = encode_varint(p, s->id);

		if (s->tx_next > 0) {
			*hdr |= STREAM_OFF_FLAG;
			p = encode_varint(p, s->tx_next);
		}

		size_t pktsz = (size_t)(e - p - 2);
		uint16_t sz = (uint16_t)qbuf_copy(&s->tx, s->tx_next, p, MIN(flowsz, pktsz));
		if (!c->handshake_complete) {
			*hdr |= STREAM_LEN_FLAG;
			p = encode_varint(p, sz);
		}
		p += sz;

		if ((s->flags & QS_TX_FIN) && (s->tx_next + sz) == s->tx.tail) {
			*hdr |= STREAM_FIN_FLAG;
			pkt->flags |= QPKT_FIN;
		} else {
			assert(sz || not_started);
		}

		pkt->off = s->tx_next;
		pkt->len = sz;
		LOG(c->local_cfg->debug, "TX STREAM %"PRIu64", off %"PRIu64", len %d", s->id, pkt->off, pkt->len);
	}

	if (p > begin) {
		pkt->stream = s;
		pkt->flags |= QPKT_SEND;
	}

	return p;
}

void q_commit_stream(struct connection *c, qstream_t *s, qtx_packet_t *pkt) {
	if (pkt->flags & QPKT_STREAM_DATA) {
		s->rx_max_allowed = qbuf_max(&s->rx);
	}
	if (pkt->flags & QPKT_STOP) {
		s->flags &= ~QS_TX_STOP_SEND;
	}
	if (pkt->flags & QPKT_RST) {
		s->flags &= ~QS_TX_RST_SEND;
	}
	if (pkt->flags & QPKT_FIN) {
		s->flags &= ~QS_TX_FIN_SEND;
	}
	if (pkt->len) {
		qbuf_mark_invalid(&s->tx, pkt->off, pkt->len);
		uint64_t pktend = pkt->off + pkt->len;
		if (pktend > s->tx_max_sent) {
			uint64_t new_data = s->tx_next - s->tx_max_sent;
			c->tx_data += new_data;
			s->tx_max_sent = pktend;
			s->tx_next = pktend;
		} else {
			s->tx_next = qbuf_next_valid(&s->tx, pktend, s->tx.tail);
		}
	}
	insert_stream_packet(s, pkt, pkt->off);
	s->flags &= ~QS_TX_CONTROL;
}

void q_ack_stream(struct connection *c, qstream_t *s, qtx_packet_t *pkt) {
	pkt->stream = NULL;

	if (pkt->flags & QPKT_STOP) {
		s->flags |= QS_RX_STOP_ACK;
	}
	if (pkt->flags & QPKT_RST) {
		s->flags |= QS_RX_RST_ACK;
	}
	if (pkt->flags & QPKT_FIN) {
		s->flags |= QS_RX_FIN_ACK;
	}
	bool sent = !(s->flags & QS_TX_RST) && pkt->off == s->tx.head && pkt->len;
	if (sent) {
		qbuf_consume(&s->tx, pkt->len);
		if (s->tx.head < s->tx_max_sent) {
			rbnode *n = rb_next(&pkt->rb, RB_RIGHT);
			s->tx.head = qbuf_next_valid(&s->tx, s->tx.head, n ? container_of(n, qtx_packet_t, rb)->off : s->tx_max_sent);
		}
	}
	if (((s->flags & QS_RX_FIN_ACK) && (s->tx.head == s->tx.tail)) || (s->flags & QS_RX_RST_ACK)) {
		s->flags |= QS_TX_COMPLETE;
	}
	s->flags |= QS_STARTED;
	rb_remove(&s->packets, &pkt->rb);
	if (sent && (*c->iface)->data_sent) {
		(*c->iface)->data_sent(c->iface, s);
	}
	remove_stream_if_complete(c, s);
}

void q_lost_stream(struct connection *c, qstream_t *s, qtx_packet_t *pkt) {
	pkt->stream = NULL;

	if ((pkt->flags & QPKT_STOP) && !(s->flags & QS_RX_STOP_ACK)) {
		s->flags |= QS_TX_STOP_SEND | QS_TX_CONTROL;
	}
	if ((pkt->flags & QPKT_RST) && !(s->flags & QS_RX_RST_ACK)) {
		s->flags |= QS_TX_RST_SEND | QS_TX_CONTROL;
	}
	if ((pkt->flags & QPKT_FIN) && !(s->flags & QS_RX_FIN_ACK)) {
		s->flags |= QS_TX_FIN_SEND | QS_TX_CONTROL;
	}
	if (!(s->flags & QS_STARTED)) {
		s->flags |= QS_NOT_STARTED | QS_TX_CONTROL;
	}
	if (!(s->flags & QS_TX_RST) && pkt->len) {
		qbuf_mark_valid(&s->tx, pkt->off, pkt->len);
		if (pkt->off < s->tx_next) {
			s->tx_next = pkt->off;
		}
	}
	rb_remove(&s->packets, &pkt->rb);
	qc_flush((qconnection_t*)c, s);
}





