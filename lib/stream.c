#include "internal.h"
#include <inttypes.h>

void qinit_stream(qstream_t *s, void *txbuf, size_t txlen, void *rxbuf, size_t rxlen) {
	memset(s, 0, sizeof(*s));
	qbuf_init(&s->rx, rxbuf, rxlen); 
	qbuf_init(&s->tx, txbuf, txlen);
	s->id = UINT64_MAX;
}

void q_setup_remote_stream(qconnection_t *c, qstream_t *s, uint64_t id) {
	bool uni = (id & STREAM_UNI_MASK) == STREAM_UNI;
	if (uni) {
		qbuf_init(&s->tx, NULL, 0);
		s->flags |= QTX_COMPLETE | QTX_RST | QTX_RST_SENT | QRX_RST_ACK;
		s->tx_max = 0;
		s->rx_max = c->local_cfg->stream_data_uni;
		s->rx_end = UINT64_MAX;
	} else {
		s->tx_max = c->peer_cfg.stream_data_bidi_local;
		s->rx_max = c->local_cfg->stream_data_bidi_remote;
		s->rx_end = UINT64_MAX;
	}
	s->id = id;
}

void q_setup_local_stream(qconnection_t *c, qstream_t *s, uint64_t id) {
	bool uni = (id & STREAM_UNI_MASK) == STREAM_UNI;
	if (uni) {
		qbuf_init(&s->rx, NULL, 0);
		s->flags |= QRX_COMPLETE | QTX_STOP | QTX_STOP_SENT | QRX_STOP_ACK;
		s->tx_max = c->peer_cfg.stream_data_uni;
		s->rx_max = 0;
		s->rx_end = 0;
	} else {
		s->tx_max = c->peer_cfg.stream_data_bidi_remote;
		s->rx_max = c->local_cfg->stream_data_bidi_local;
		s->rx_end = UINT64_MAX;
	}
	s->id = id;
}

bool qrx_error(qstream_t *s) {
	return (s->flags | QRX_RST) != 0;
}

void qrx_stop(qstream_t *s, int errnum) {
	if (!(s->flags & QTX_STOP)) {
		s->flags |= QRX_COMPLETE | QTX_STOP | QTX_DIRTY;
		s->stop_errnum = errnum;
		qbuf_init(&s->rx, NULL, 0);
	}
}

size_t qrx_read(qstream_t *s, void *data, size_t len) {
	if (s->flags & (QTX_STOP | QRX_RST)) {
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
	if (!(s->flags & QTX_RST)) {
		s->rst_errnum = errnum;
		s->flags |= QTX_RST | QTX_DIRTY;
		qbuf_init(&s->tx, NULL, 0);
	}
}

void qtx_finish(qstream_t *s) {
	if (!(s->flags & QTX_FIN)) {
		s->flags |= QTX_FIN | QTX_DIRTY;
	}
}

void qtx_write(qstream_t *s, const void *data, size_t len) {
	qbuf_insert(&s->tx, s->tx.tail, data, len);
	qbuf_fold(&s->tx);
}

static void remove_stream_if_complete(qconnection_t *c, qstream_t *s) {
	assert(s->id >= 0);
	if ((s->flags & QRX_COMPLETE) && (s->flags & QTX_COMPLETE)) {
		q_remove_stream(c, s);
	}
}

int q_recv_stream(qconnection_t *c, qstream_t *s, bool fin, uint64_t off, const void *p, size_t sz) {
	uint64_t end = off + sz;
	if (end > qbuf_max(&s->rx)) {
		return QC_ERR_FLOW_CONTROL;
	} else if (end > s->rx_end) {
		return QC_ERR_FINAL_OFFSET;
	} else if (s->flags & (QTX_STOP | QRX_RST | QRX_COMPLETE)) {
		return 0;
	}

	if (fin) {
		if (s->rx_end == UINT64_MAX) {
			s->rx_end = end;
			s->flags |= QRX_FIN;
		} else if (s->rx_end != end) {
			return QC_ERR_FINAL_OFFSET;
		}
	}

	size_t ret = qbuf_insert(&s->rx, off, p, sz);
	if (ret && s->rx.tail == s->rx_end) {
		s->flags |= QRX_COMPLETE;
	} else if (ret) {
		// schedule the stream to transmit to update flow control
		s->flags |= QTX_DIRTY;
		qc_flush(c, s);
	}

	if (ret && (*c->iface)->data_received) {
		(*c->iface)->data_received(c->iface, s);
	}

	qbuf_fold(&s->rx);
	remove_stream_if_complete(c, s);
	return 0;
}

int q_recv_max_stream(qconnection_t *c, qstream_t *s, uint64_t off) {
	s->tx_max = MAX(s->tx_max, off);
	return 0;
}

int q_recv_stop(qconnection_t *c, qstream_t *s, int errnum) {
	s->rx_errnum = errnum;
	s->flags |= QRX_STOP;
	qtx_cancel(s, QRST_STOPPING);
	return 0;
}

int q_recv_reset(qconnection_t *c, qstream_t *s, int errnum, uint64_t off) {
	if (s->flags & QRX_RST) {
		return 0;
	} else if (qbuf_any_valid_after(&s->rx, off)) {
		// hang on, we've received data after the "final offset"
		return QC_ERR_PROTOCOL_VIOLATION;
	}

	s->rx_data = off;
	s->rx_errnum = errnum;
	s->flags |= QRX_RST | QRX_COMPLETE | QTX_STOP | QTX_STOP_SENT | QRX_STOP_ACK;
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

static bool at_tx_eof(qstream_t *s, uint64_t off) {
	return (s->flags & QTX_FIN) && (off == s->tx.tail);
}

int q_encode_stream(qconnection_t *c, qslice_t *p, qstream_t *s, uint64_t *poff, qtx_packet_t *pkt) {
	if (p->p + 1 + 8 + 8 + 2 > p->e) {
		return -1;
	}
	assert(s->id != UINT64_MAX);

	// send in every packet for now
	uint64_t new_max = qbuf_max(&s->rx);
	if (new_max > s->rx_max) {
		s->rx_max = new_max;
		*(p->p++) = MAX_STREAM_DATA;
		p->p = encode_varint(p->p, s->id);
		p->p = encode_varint(p->p, s->rx_max);
		pkt->flags |= QTX_PKT_STREAM_DATA;
		pkt->stream = s;
	}

	if ((s->flags & QTX_STOP) && !(s->flags & QTX_STOP_SENT)) {
		*(p->p++) = STOP_SENDING;
		p->p = encode_varint(p->p, s->id);
		p->p = write_big_16(p->p, (uint16_t)(s->stop_errnum - QC_ERR_APP_OFFSET));
		s->flags |= QTX_STOP_SENT;
		pkt->flags |= QTX_PKT_RETRANSMIT | QTX_PKT_STOP;
		pkt->stream = s;
	}

	if ((s->flags & QTX_RST) && !(s->flags & QTX_RST_SENT)) {
		*(p->p++) = RST_STREAM;
		p->p = encode_varint(p->p, s->id);
		p->p = write_big_16(p->p, (uint16_t)(s->rst_errnum - QC_ERR_APP_OFFSET));
		p->p = encode_varint(p->p, s->tx.tail);
		s->flags |= QTX_RST_SENT;
		pkt->flags |= QTX_PKT_RETRANSMIT | QTX_PKT_RST;
		pkt->stream = s;
	}

	if ((qbuf_next_valid(&s->tx, poff) && *poff < s->tx_max) || ((s->flags & QTX_FIN) && !(s->flags & QTX_FIN_SENT))) {
		uint8_t *stream_header = p->p;
		*(p->p++) = STREAM | STREAM_LEN_FLAG;
		p->p = encode_varint(p->p, s->id);
		if (*poff > 0) {
			*stream_header |= STREAM_OFF_FLAG;
			p->p = encode_varint(p->p, *poff);
		}
		p->p += 2;
		uint64_t pktend = *poff + (uint64_t)(p->e - p->p);
		uint64_t sflow = s->tx_max;
		uint64_t cflow = s->tx_sent + c->tx_max_data - c->data_sent;
		uint64_t end = MIN(pktend, MIN(cflow, sflow));
		uint16_t sz = (uint16_t)qbuf_copy(&s->tx, *poff, p->p, (size_t)(end - *poff));
		write_big_16(p->p - 2, VARINT_16 | sz);
		p->p += sz;
		qbuf_mark_invalid(&s->tx, *poff, sz);

		bool have_fin = at_tx_eof(s, *poff + sz);

		if (have_fin || sz) {
			if (have_fin) {
				*stream_header |= STREAM_FIN_FLAG;
				s->flags |= QTX_FIN_SENT;
				pkt->flags |= QTX_PKT_FIN;
			}
			if (sz) {
				pkt->off = *poff;
				pkt->len = sz;
				pkt->flags |= QTX_PKT_RETRANSMIT;
				pkt->stream = s;
				insert_stream_packet(s, pkt, *poff);
			}
			if (*poff + sz > s->tx_sent) {
				uint64_t new_data = *poff + sz - s->tx_sent;
				c->data_sent += new_data;
				s->tx_sent = *poff + sz;
			}
			LOG(c->local_cfg->debug, "TX STREAM %"PRIu64", off %"PRIu64", len %d", s->id, pkt->off, pkt->len);
		} else {
			// no point to having a stream frame
			p->p = stream_header;
		}
	}

	return 0;
}

void q_ack_stream(qconnection_t *c, qtx_packet_t *pkt) {
	qstream_t *s = pkt->stream;
	rb_remove(&s->tx_packets, &pkt->rb);
	pkt->stream = NULL;

	if (pkt->flags & QTX_PKT_STOP) {
		s->flags |= QRX_STOP_ACK;
	}
	if (pkt->flags & QTX_PKT_RST) {
		s->flags |= QRX_RST_ACK;
	}
	if (pkt->flags & QTX_PKT_FIN) {
		s->flags |= QRX_FIN_ACK;
	}
	if (!(s->flags & QTX_RST) && pkt->off == s->tx.head && pkt->len) {
		rbnode *n = rb_next(&pkt->rb, RB_RIGHT);
		size_t len = qbuf_consume(&s->tx, n ? container_of(n, qtx_packet_t, rb)->off : s->tx.tail);
		if (at_tx_eof(s, s->tx.head)) {
			s->flags |= QRX_DATA_ACK;
		}
		if (len && (*c->iface)->data_sent) {
			(*c->iface)->data_sent(c->iface, s);
		}
	}
	if (((s->flags & QRX_FIN_ACK) && (s->flags & QRX_DATA_ACK)) || (s->flags & QRX_RST_ACK)) {
		s->flags |= QTX_COMPLETE;
	}
	remove_stream_if_complete(c, s);
}

void q_lost_stream(qconnection_t *c, qtx_packet_t *pkt) {
	qstream_t *s = pkt->stream;
	rb_remove(&s->tx_packets, &pkt->rb);
	pkt->stream = NULL;

	if (pkt->flags & QTX_PKT_STOP && !(s->flags & QRX_STOP_ACK)) {
		s->flags &= ~QTX_STOP_SENT;
	}
	if (pkt->flags & QTX_PKT_RST && !(s->flags & QRX_RST_ACK)) {
		s->flags &= ~QTX_RST_SENT;
	}
	if (pkt->flags & QTX_PKT_FIN && !(s->flags & QRX_FIN_ACK)) {
		s->flags &= ~QTX_FIN_SENT;
	}
	if (!(s->flags & QTX_RST) && pkt->len) {
		qbuf_mark_valid(&s->tx, pkt->off, pkt->len);
	}
}





