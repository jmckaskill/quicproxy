#include "internal.h"
#include <inttypes.h>

void qinit_stream(qstream_t *s, void *rxbuf, size_t rxlen) {
	memset(s, 0, offsetof(qstream_t, to_send));
	qbuf_init(&s->rx, rxbuf, rxlen); 
	s->id = UINT64_MAX;
}

void q_setup_remote_stream(struct connection *c, qstream_t *s, uint64_t id) {
	bool uni = (id & STREAM_UNI_MASK) == STREAM_UNI;
	if (uni) {
		s->flags &= ~QS_TX_RST_SEND;
		s->flags |= QS_TX_COMPLETE | QS_TX_RST | QS_RX_RST_ACK;
		s->rx_max_allowed = c->local_cfg->stream_data_uni;
		s->to_send_num = 0;
		s->source = NULL;
	} else {
		s->to_send_num = 1;
		s->to_send[0].start = 0;
		s->to_send[0].end = c->peer_cfg.stream_data_bidi_local;
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
		s->rx_max_allowed = 0;
		s->to_send[0].end = c->peer_cfg.stream_data_uni;
	} else {
		s->flags |= QS_TX_CONTROL;
		s->rx_max_allowed = c->local_cfg->stream_data_bidi_local;
		s->to_send[0].end = c->peer_cfg.stream_data_bidi_remote;
	}
	s->to_send[0].start = 0;
	s->to_send_num = 1;
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
		s->to_send_num = 0;
		s->source = NULL;
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
	assert(s->rx_max_allowed <= qbuf_max(&s->rx));
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
	if (s->to_send_num && off > s->to_send[0].end) {
		s->to_send[0].end = off;
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

static uint8_t *encode_reset(qstream_t *s, uint8_t *p, qtx_packet_t *pkt) {
	*(p++) = RST_STREAM;
	p = q_encode_varint(p, s->id);
	p = write_big_16(p, (uint16_t)(s->rst_errnum - QC_ERR_APP_OFFSET));
	p = q_encode_varint(p, s->tx_max_sent);
	pkt->flags |= QPKT_RST;
	pkt->len = 0;
	pkt->off = 0;
	return p;
}

uint8_t *q_encode_stream(struct connection *c, qstream_t *s, uint8_t *p, uint8_t *e, qtx_packet_t *pkt, bool pad, q_continue_fn fn, void *user) {
	uint8_t *begin = p;

	uint64_t new_max = qbuf_max(&s->rx);
	if (new_max > s->rx_max_allowed && !(s->flags & QS_TX_STOP)) {
		*(p++) = MAX_STREAM_DATA;
		p = q_encode_varint(p, s->id);
		p = q_encode_varint(p, new_max);
		pkt->flags |= QPKT_STREAM_DATA;
	}

	if (s->flags & QS_TX_STOP_SEND) {
		*(p++) = STOP_SENDING;
		p = q_encode_varint(p, s->id);
		p = write_big_16(p, (uint16_t)(s->stop_errnum - QC_ERR_APP_OFFSET));
		pkt->flags |= QPKT_STOP;
	}

	if (s->flags & QS_TX_RST_SEND) {
		return encode_reset(s, p, pkt);
	}

	bool not_started = (s->flags & QS_NOT_STARTED);

	if (s->to_send_num && (not_started || s->source)) {
		struct qstream_tx_range *r = &s->to_send[s->to_send_num - 1];
		uint8_t *hdr = p;
		*p++ = STREAM;
		p = q_encode_varint(p, s->id);
		if (r->start > 0) {
			*hdr |= STREAM_OFF_FLAG;
			p = q_encode_varint(p, r->start);
		}
		uint8_t *len = p;
		if (pad) {
			// add a length so that we can append padding
			*hdr |= STREAM_LEN_FLAG;
			p += 2;
		}
		size_t sz = 0;
		uint64_t cflow = s->tx_max_sent + c->tx_data_max - c->tx_data;
		size_t maxsz = MIN((size_t)(MIN(cflow, r->end) - r->start), (size_t)(e - p));

		if (!s->source) {
			s->cont.fn = fn;
			s->cont.user = user;
		} else {
			for (;;) {
				const void *data;
				ssize_t n = (*s->source)->read(s->source, r->start + sz, 1, &data, fn, user);

				if (n == QPENDING) {
					break;
				} else if (n < 0) {
					s->flags |= QS_TX_RST_SEND;
					s->rst_errnum = -(int)n;
					s->to_send_num = 0;
					s->source = NULL;
					return encode_reset(s, hdr, pkt);
				} else if (!n) {
					*hdr |= STREAM_FIN_FLAG;
					pkt->flags |= QPKT_FIN;
				} else if (n > maxsz - sz) {
					n = maxsz - sz;
				}

				if (n) {
					memcpy(p, data, (size_t)n);
					sz += n;
					p += n;
				} else {
					break;
				}
			}
		}

		bool new_fin = (pkt->flags & QPKT_FIN) && (s->flags & QS_TX_FIN_SEND);
		if (sz || not_started || new_fin) {
			if (pad) {
				write_big_16(len, VARINT_16 | sz);
			}
			pkt->off = r->start;
			pkt->len = sz;
		} else {
			p = hdr;
		}
	}

	if (p > begin) {
		pkt->stream = s;
		pkt->flags |= QPKT_SEND;
	}

	if (pad) {
		memset(p, 0, (size_t)(e - p));
		return e;
	} else {
		return p;
	}
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
		struct qstream_tx_range *r = &s->to_send[s->to_send_num - 1];
		r->start += pkt->len;
		if (r->start == r->end && s->to_send_num > 1) {
			s->to_send_num--;
		}
		uint64_t pktend = pkt->off + pkt->len;
		if (pktend > s->tx_max_sent) {
			uint64_t new_data = pktend - s->tx_max_sent;
			c->tx_data += new_data;
			s->tx_max_sent = pktend;
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
	bool sent = s->source && pkt->off == s->tx_min_ack && pkt->len;
	if (sent) {
		uint64_t pktend = pkt->off + pkt->len;
		rbnode *n = rb_next(&pkt->rb, RB_RIGHT);
		uint64_t nextinflight = n ? container_of(n, qtx_packet_t, rb)->off : pktend;
		uint64_t nextack = MIN(nextinflight, s->to_send[s->to_send_num - 1].start);
		(*s->source)->seek(s->source, (size_t)(nextack - s->tx_min_ack));
		s->tx_min_ack = nextack;
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

static size_t find_bounding_ranges(qstream_t *s, uint64_t off, struct qstream_tx_range **prev, struct qstream_tx_range **next) {
	size_t n = s->to_send_num;
	size_t i = 0;

	while (n) {
		size_t step = n / 2;
		size_t mid = i + step;
		if (s->to_send[i].start >= off) {
			i = mid + 1;
			n -= step - 1;
		} else {
			n = step;
		}
	}

	*next = i ? &s->to_send[i - 1] : NULL;
	*prev = (i < s->to_send_num) ? &s->to_send[i] : NULL;
	return i;
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
	if (s->to_send_num && pkt->len) {
		uint64_t off = pkt->off;
		uint64_t end = off + pkt->len;
		struct qstream_tx_range *prev, *next;
		size_t idx = find_bounding_ranges(s, off, &prev, &next);

		if (prev && off <= prev->end) {
			// grow previous
			prev->end = MAX(prev->end, end);
		} else if (next && end >= next->start) {
			// grow next
			next->start = MIN(next->start, off);
		} else if (s->to_send_num < QSTREAM_MAX_TX_RANGES) {
			// insert new between the two
			struct qstream_tx_range *r = &s->to_send[idx];
			memmove(r + 1, r, (s->to_send_num - idx) * sizeof(*r));
			r->start = off;
			r->end = end;
			s->to_send_num++;
		} else if (!next || (prev && (off - prev->end) < (next->start - end))) {
			// We have to grow next or previous more than strictly necessary.
			// This will result in data retransmission.
			// Growing previous results in less retransmission.
			prev->end = end;
		} else {
			// Growing next results in less retransmission.
			next->start = off;
		}
	}
	rb_remove(&s->packets, &pkt->rb);
	qc_flush((qconnection_t*)c, s);
}





