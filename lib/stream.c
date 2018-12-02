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
		s->flags |= QS_TX_COMPLETE | QS_TX_RST | QS_TX_RST_SENT | QS_RX_RST_ACK;
		s->tx_max_allowed = 0;
		s->rx_max_allowed = c->local_cfg->stream_data_uni;
		s->rx_stream_end = UINT64_MAX;
	} else {
		s->tx_max_allowed = c->peer_cfg.stream_data_bidi_local;
		s->rx_max_allowed = c->local_cfg->stream_data_bidi_remote;
		s->rx_stream_end = UINT64_MAX;
	}
	assert(qbuf_max(&s->rx) >= s->rx_max_allowed);
	s->id = id;
	s->flags |= QS_TX_START_SENT | QS_TX_START_ACK;
}

void q_setup_local_stream(struct connection *c, qstream_t *s, uint64_t id) {
	bool uni = (id & STREAM_UNI_MASK) == STREAM_UNI;
	if (uni) {
		qbuf_init(&s->rx, NULL, 0);
		s->flags |= QS_RX_COMPLETE | QS_TX_STOP | QS_TX_STOP_SENT | QS_RX_STOP_ACK;
		s->tx_max_allowed = c->peer_cfg.stream_data_uni;
		s->rx_max_allowed = 0;
		s->rx_stream_end = 0;
	} else {
		s->tx_max_allowed = c->peer_cfg.stream_data_bidi_remote;
		s->rx_max_allowed = c->local_cfg->stream_data_bidi_local;
		s->rx_stream_end = UINT64_MAX;
	}
	assert(qbuf_max(&s->rx) >= s->rx_max_allowed);
	s->id = id;
}

bool qrx_error(qstream_t *s) {
	return (s->flags | QS_RX_RST) != 0;
}

void qrx_stop(qstream_t *s, int errnum) {
	if (!(s->flags & QS_TX_STOP)) {
		s->flags |= QS_RX_COMPLETE | QS_TX_STOP | QS_TX_DIRTY;
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
		qbuf_mark_invalid(&s->rx, off, len);
		qbuf_consume(&s->rx, off + len);
		return len;
	}
}

void qtx_cancel(qstream_t *s, int errnum) {
	if (!(s->flags & QS_TX_RST)) {
		s->rst_errnum = errnum;
		s->flags |= QS_TX_RST | QS_TX_DIRTY;
		qbuf_init(&s->tx, NULL, 0);
	}
}

void qtx_finish(qstream_t *s) {
	if (!(s->flags & QS_TX_FIN)) {
		s->flags |= QS_TX_FIN | QS_TX_DIRTY;
	}
}

void qtx_write(qstream_t *s, const void *data, size_t len) {
	qbuf_insert(&s->tx, s->tx.tail, data, len);
	qbuf_fold(&s->tx);
	s->flags |= QS_TX_DIRTY;
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
		if (c->data_received + new_data > c->rx_max_data) {
			return -1;
		}
		c->data_received += new_data;
		s->rx_max_received = end;
		// schedule a send to update connection max data
		q_async_send_data(c);
	}
	return 0;
}

int q_recv_stream(struct connection *c, qstream_t *s, bool fin, uint64_t off, const void *p, size_t sz) {
	uint64_t end = off + sz;
	if (update_recv_flow(c, s, end)) {
		return QC_ERR_FLOW_CONTROL;
	} else if (end > s->rx_stream_end) {
		return QC_ERR_FINAL_OFFSET;
	} else if (s->flags & (QS_TX_STOP | QS_RX_RST | QS_RX_COMPLETE)) {
		return 0;
	}

	if (fin) {
		if (s->rx_stream_end == UINT64_MAX) {
			s->rx_stream_end = end;
			s->flags |= QS_RX_FIN;
		} else if (s->rx_stream_end != end) {
			return QC_ERR_FINAL_OFFSET;
		}
	}

	size_t ret = qbuf_insert(&s->rx, off, p, sz);
	if (ret && s->rx.tail == s->rx_stream_end) {
		s->flags |= QS_RX_COMPLETE;
	}

	if (ret && (*c->iface)->data_received) {
		(*c->iface)->data_received(c->iface, s);
	}

	qbuf_fold(&s->rx);
	remove_stream_if_complete(c, s);
	return 0;
}

int q_recv_max_stream(struct connection *c, qstream_t *s, uint64_t off) {
	s->tx_max_allowed = MAX(s->tx_max_allowed, off);
	qc_flush((qconnection_t*)c, s);
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
	} else if (s->flags & QS_RX_RST) {
		return 0;
	}

	s->rx_errnum = errnum;
	s->flags |= QS_RX_RST | QS_RX_COMPLETE | QS_TX_STOP | QS_TX_STOP_SENT | QS_RX_STOP_ACK;
	qbuf_init(&s->rx, NULL, 0);

	if ((*c->iface)->data_received) {
		(*c->iface)->data_received(c->iface, s);
	}
	remove_stream_if_complete(c, s);
	return 0;
}

static void insert_stream_packet(qstream_t *s, qtx_packet_t *pkt, uint64_t off) {
	rbnode *p = s->tx_packets.root;
	rbdirection dir = RB_LEFT;
	while (p) {
		qtx_packet_t *pp = container_of(p, qtx_packet_t, rb);
		dir = (pp->off < off) ? RB_LEFT : RB_RIGHT;
		if (!rb_child(p, dir)) {
			break;
		}
		p = rb_child(p, dir);
	}
	rb_insert(&s->tx_packets, p, &pkt->rb, dir);
}

static bool at_tx_eof(const qstream_t *s, uint64_t off) {
	return (s->flags & QS_TX_FIN) && (off == s->tx.tail);
}

size_t q_stream_cwnd_size(const qtx_packet_t *pkt) {
	size_t ret = 0;
	if (pkt->flags & QPKT_STREAM_DATA) {
		ret += 1 + 4 + 4;
	}
	if (pkt->flags & QPKT_STOP) {
		ret += 1 + 2;
	}
	if (pkt->flags & QS_TX_RST) {
		ret += 1 + 2 + 4;
	}
	if (pkt->len || (pkt->flags & QS_TX_FIN)) {
		ret += 1 + 4 + 4 + 2 + pkt->len;
	}
	return ret;
}

int q_encode_stream(struct connection *c, qslice_t *p, const qstream_t *s, uint64_t *poff, qtx_packet_t *pkt) {
	if (p->p + 1 + 8 + 8 + 2 > p->e) {
		return -1;
	}
	assert(s->id != UINT64_MAX);

	uint64_t new_max = qbuf_max(&s->rx);
	if (new_max > s->rx_max_allowed && !(s->flags & QS_TX_STOP)) {
		*(p->p++) = MAX_STREAM_DATA;
		p->p = encode_varint(p->p, s->id);
		p->p = encode_varint(p->p, new_max);
		pkt->flags |= QPKT_STREAM_DATA;
	}

	if ((s->flags & QS_TX_STOP) && !(s->flags & QS_TX_STOP_SENT)) {
		*(p->p++) = STOP_SENDING;
		p->p = encode_varint(p->p, s->id);
		p->p = write_big_16(p->p, (uint16_t)(s->stop_errnum - QC_ERR_APP_OFFSET));
		pkt->flags |= QPKT_RETRANSMIT | QPKT_STOP;
	}

	if ((s->flags & QS_TX_RST) && !(s->flags & QS_TX_RST_SENT)) {
		*(p->p++) = RST_STREAM;
		p->p = encode_varint(p->p, s->id);
		p->p = write_big_16(p->p, (uint16_t)(s->rst_errnum - QC_ERR_APP_OFFSET));
		p->p = encode_varint(p->p, s->tx.tail);
		pkt->flags |= QPKT_RETRANSMIT | QPKT_RST;
	}

	bool not_started = !(s->flags & QS_TX_START_SENT);
	if (not_started || (qbuf_next_valid(&s->tx, poff) && *poff < s->tx_max_allowed) || ((s->flags & QS_TX_FIN) && !(s->flags & QS_TX_FIN_SENT))) {
		uint8_t *stream_header = p->p;
		*(p->p++) = STREAM | STREAM_LEN_FLAG;
		p->p = encode_varint(p->p, s->id);
		if (*poff > 0) {
			*stream_header |= STREAM_OFF_FLAG;
			p->p = encode_varint(p->p, *poff);
		}
		p->p += 2;
		uint64_t pktend = *poff + (uint64_t)(p->e - p->p);
		uint64_t sflow = s->tx_max_allowed;
		uint64_t cflow = s->tx_max_sent + c->tx_max_data - c->data_sent;
		uint64_t end = MIN(pktend, MIN(cflow, sflow));
		uint16_t sz = (uint16_t)qbuf_copy(&s->tx, *poff, p->p, (size_t)(end - *poff));
		write_big_16(p->p - 2, VARINT_16 | sz);
		p->p += sz;

		bool have_fin = at_tx_eof(s, *poff + sz);

		if (have_fin || sz || not_started) {
			if (have_fin) {
				*stream_header |= STREAM_FIN_FLAG;
				pkt->flags |= QPKT_FIN;
			}
			if (sz || not_started) {
				pkt->off = *poff;
				pkt->len = sz;
				pkt->flags |= QPKT_RETRANSMIT;
			}
			LOG(c->local_cfg->debug, "TX STREAM %"PRIu64", off %"PRIu64", len %d", s->id, pkt->off, pkt->len);
		} else {
			// no point to having a stream frame
			p->p = stream_header;
		}
	}

	if (!(pkt->flags & (QPKT_RETRANSMIT | QPKT_FIN | QPKT_RST | QPKT_STREAM_DATA | QPKT_STOP))) {
		// We had no stream specific data, but the calling code was trying to 
		// flush this stream. We should return an error so the calling code
		// stops trying to send this packet.
		return -1;
	}

	return 0;
}

void q_commit_stream(struct connection *c, qstream_t *s, qtx_packet_t *pkt) {
	if (pkt->flags & QPKT_STREAM_DATA) {
		s->rx_max_allowed = qbuf_max(&s->rx);
	}
	if (pkt->flags & QPKT_STOP) {
		s->flags |= QS_TX_STOP_SENT;
	}
	if (pkt->flags & QPKT_RST) {
		s->flags |= QS_TX_RST_SENT;
	}
	if (pkt->flags & QPKT_FIN) {
		s->flags |= QS_TX_FIN_SENT;
	}
	if (pkt->len) {
		qbuf_mark_invalid(&s->tx, pkt->off, pkt->len);
		uint64_t end = pkt->off + pkt->len;
		if (end > s->tx_max_sent) {
			uint64_t new_data = end - s->tx_max_sent;
			c->data_sent += new_data;
			s->tx_max_sent = end;
		}
	}
	s->flags |= QS_TX_START_SENT;
	insert_stream_packet(s, pkt, pkt->off);
	pkt->stream = s;
}

void q_ack_stream(struct connection *c, qtx_packet_t *pkt) {
	qstream_t *s = pkt->stream;
	rb_remove(&s->tx_packets, &pkt->rb);
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
	if (!(s->flags & QS_TX_RST) && pkt->off == s->tx.head && pkt->len) {
		rbnode *n = rb_next(&pkt->rb, RB_RIGHT);
		size_t len = qbuf_consume(&s->tx, n ? container_of(n, qtx_packet_t, rb)->off : s->tx.tail);
		if (at_tx_eof(s, s->tx.head)) {
			s->flags |= QS_RX_DATA_ACK;
		}
		if (len && (*c->iface)->data_sent) {
			(*c->iface)->data_sent(c->iface, s);
		}
	}
	if (((s->flags & QS_RX_FIN_ACK) && (s->flags & QS_RX_DATA_ACK)) || (s->flags & QS_RX_RST_ACK)) {
		s->flags |= QS_TX_COMPLETE;
	}
	s->flags |= QS_TX_START_ACK;
	remove_stream_if_complete(c, s);
}

void q_lost_stream(struct connection *c, qtx_packet_t *pkt) {
	qstream_t *s = pkt->stream;
	rb_remove(&s->tx_packets, &pkt->rb);
	pkt->stream = NULL;

	if (pkt->flags & QPKT_STOP && !(s->flags & QS_RX_STOP_ACK)) {
		s->flags &= ~QS_TX_STOP_SENT;
	}
	if (pkt->flags & QPKT_RST && !(s->flags & QS_RX_RST_ACK)) {
		s->flags &= ~QS_TX_RST_SENT;
	}
	if (pkt->flags & QPKT_FIN && !(s->flags & QS_RX_FIN_ACK)) {
		s->flags &= ~QS_TX_FIN_SENT;
	}
	if (!(s->flags & QS_TX_START_ACK)) {
		s->flags &= ~QS_TX_START_SENT;
	}
	if (!(s->flags & QS_TX_RST) && pkt->len) {
		qbuf_mark_valid(&s->tx, pkt->off, pkt->len);
	}
	s->flags |= QS_TX_DIRTY;
	qc_flush((qconnection_t*)c, s);
}





