#include "internal.h"
#include "connection.h"

static void add_local_stream(qconnection_t *c, qstream_t *s) {
	int uni = s->rx.size ? 1 : 0;
	uint64_t id = ((c->next_stream_id[uni]++) << 2) | uni | (c->is_client ? STREAM_CLIENT : STREAM_SERVER);
	q_setup_local_stream(s, id, c->peer_cfg.stream_data_bidi_remote, c->peer_cfg.stream_data_uni);
	rbtree *rx = &c->rx_streams[id & 3];
	rb_insert(rx, rb_begin(rx, RB_RIGHT), &s->rxnode, RB_RIGHT);
}

static int create_remote_stream(qconnection_t *c, uint64_t id, qstream_t **ps) {
	if ((id >> 2) >= c->max_stream_id[id & 3]) {
		return QC_ERR_STREAM_ID;
	}

	rbnode *n = c->rx_streams[id & 3].root;
	while (n) {
		qstream_t *s = container_of(n, qstream_t, rxnode);
		if (s->id == id) {
			*ps = s;
			return 0;
		}
		n = (id < s->id) ? n->child[RB_LEFT] : n->child[RB_RIGHT];
	}

	if ((id >> 2) < c->next_stream_id[id & 3]
		|| (id & STREAM_SERVER) == (c->is_client ? 0 : STREAM_SERVER)) {
		// this must be an out of order frame from an old stream
		// we already closed
		*ps = NULL;
		return 0;
	}

	if (!(*c->iface)->new_stream) {
		return QC_ERR_INTERNAL;
	}

	// now we need to create the stream (and all the intermediate streams)
	bool uni = (id & STREAM_UNI_MASK) == STREAM_UNI;
	rbnode *n = rb_begin(&c->rx_streams[id & 3], RB_RIGHT);
	while (c->next_stream_id[id & 3] <= (id >> 2)) {
		qstream_t *s = (*c->iface)->new_stream(c->iface, uni);
		if (!s) {
			return QC_ERR_INTERNAL;
		}
		*ps = s;
		q_setup_remote_stream(s, (c->next_stream_id[id & 3]++ << 2) | (id & 3), c->peer_cfg.stream_data_bidi_local);
		rb_insert(&c->rx_streams[id & 3], n, &s->rxnode, RB_RIGHT);
		n = &s->rxnode;
		if (s->flags & QTX_DIRTY) {
			rb_insert(&c->tx_streams, rb_begin(&c->tx_streams, RB_RIGHT), &s->txnode, RB_RIGHT);
			s->flags |= QTX_QUEUED;
		}
	}
	return 0;
}

static int send_stream(qconnection_t *c, qstream_t *s, int ignore_cwnd_pkts, tick_t *pnow) {
	struct short_packet sp = {
		.stream = s,
		.stream_off = s->tx.head,
		.send_ack = true,
	};
	qbuf_next_valid(&s->tx, &sp.stream_off);
	int sent = 0;
	for (;;) {
		sp.ignore_cwnd = (sent < ignore_cwnd_pkts);
		if (!q_send_short_packet(c, &sp, pnow)) {
			rb_insert(&c->tx_streams, rb_begin(&c->tx_streams, RB_RIGHT), RB_RIGHT);
			return sent;
		}
		sent++;
		if (qbuf_next_valid(&s->tx, &sp.stream_off)) {
			return sent;
		}
	}
}

int q_send_data(qconnection_t *c, int ignore_cwnd_pkts, tick_t now) {
	if (!c->peer_verified) {
		return -1;
	}
	int sent = 0;

	for (rbnode *n = rb_begin(&c->tx_streams, RB_LEFT); n != NULL;) {
		qstream_t *s = container_of(n, qstream_t, txnode);
		n = rb_next(n, RB_RIGHT);
		rb_remove(&c->tx_streams, &s->txnode);

		int ret = send_stream(c, s, ignore_cwnd_pkts, &now);
		ignore_cwnd_pkts -= ret;
		sent += ret;
	}

	for (int uni = 0; uni <= 1; uni++) {
		rbtree *p = &c->pending_streams[uni];
		for (rbnode *n = rb_begin(p, RB_LEFT); n != NULL && c->next_stream_id[uni] < c->max_stream_id[uni];) {
			qstream_t *s = container_of(n, qstream_t, txnode);
			n = rb_next(n, RB_RIGHT);
			rb_remove(p, &s->txnode);
			s->flags &= ~QTX_PENDING;

			add_local_stream(c, s);

			rbtree *rx = &c->rx_streams[s->id & 3];
			rb_insert(rx, rb_begin(rx, RB_RIGHT), &s->rxnode, RB_RIGHT);

			int ret = send_stream(c, s, ignore_cwnd_pkts, &now);
			ignore_cwnd_pkts -= ret;
			sent += ret;
		}
	}

	if (c->pkts[QC_PROTECTED].tx_next) {
		return sent;
	} else {
		// we need to send something to get the client finished through
		// for the client, we need a packet for the finished data
		// for the server, we need a packet to return the ack
		struct short_packet sp = {
			.ignore_cwnd = true,
			.send_ack = true,
		};
		return send_short_packet(c, &sp, &now) ? 0 : 1;
	}
}

void qc_flush(qconnection_t *c, qstream_t *s) {
	if (c->closing) {
		return;
	} else if (s->id == UINT64_MAX && !(s->flags & QTX_PENDING)) {
		bool uni = s->rx.size == 0;
		rbtree *p = &c->pending_streams[uni ? 1 : 0];
		rb_insert(p, rb_begin(p, RB_RIGHT), &s->txnode, RB_RIGHT);
		s->flags |= QTX_PENDING;
	} else if (s->id != UINT64_MAX && (s->flags & QTX_DIRTY) && !(s->flags & QTX_QUEUED)) {
		rb_insert(&c->tx_streams, rb_begin(&c->tx_streams, RB_RIGHT), &s->txnode, RB_RIGHT);
		s->flags |= QTX_QUEUED;
	} else {
		return;
	}

	if (c->peer_verified) {
		q_async_send_data(c);
	}
}

void q_remove_stream(qconnection_t *c, qstream_t *s) {
	if (s->flags & QTX_QUEUED) {
		rb_remove(&c->tx_streams, &s->txnode);
	}
	rb_remove(&c->rx_streams[s->id & 3], &s->rxnode);
	for (rbnode *n = rb_begin(&s->tx_packets, RB_LEFT); n != NULL; n = rb_next(n, RB_RIGHT)) {
		qtx_packet_t *pkt = container_of(n, qtx_packet_t, rb);
		pkt->stream = NULL;
		pkt->off = 0;
		pkt->len = 0;
	}

	if ((*c->iface)->free_stream) {
		(*c->iface)->free_stream(c->iface, s);
	}
}

static inline bool is_send_only(qconnection_t *c, uint64_t id) {
	bool uni = (id & STREAM_UNI_MASK) == STREAM_UNI;
	bool client = (id & STREAM_SERVER_MASK) == STREAM_CLIENT;
	return uni && client == c->is_client;
}

static inline bool is_recv_only(qconnection_t *c, uint64_t id) {
	bool uni = (id & STREAM_UNI_MASK) == STREAM_UNI;
	bool client = (id & STREAM_SERVER_MASK) == STREAM_CLIENT;
	return uni && client != c->is_client;
}

int q_decode_stream(qconnection_t *c, uint8_t hdr, qslice_t *p) {
	uint64_t id;
	uint64_t off = 0;
	if (decode_varint(p, &id) || ((hdr & STREAM_OFF_FLAG) && decode_varint(p, &off))) {
		return QC_ERR_FRAME_ENCODING;
	}
	uint64_t len = (uint64_t)(p->e - p->p);
	if ((hdr & STREAM_LEN_FLAG) && (decode_varint(p, &len) || len > (uint64_t)(p->e - p->p))) {
		return QC_ERR_FRAME_ENCODING;
	}
	bool fin = (hdr & STREAM_FIN_FLAG) != 0;
	void *data = p->p;
	p->p += (size_t)len;

	if (off + len >= QRX_STREAM_MAX) {
		return QC_ERR_FINAL_OFFSET;
	} else if (c->closing) {
		return 0;
	}

	qstream_t *s;
	int err = create_remote_stream(c, id, &s);
	if (err || !s) {
		return err;
	}

	return q_recv_stream(c, s, fin, off, data, (size_t)len);
}

int q_decode_stop(qconnection_t *c, qslice_t *p) {
	uint64_t id;
	if (decode_varint(p, &id) || p->p + 2 > p->e) {
		return QC_ERR_FRAME_ENCODING;
	}
	int apperr = big_16(p->p);
	p->p += 2;
	if (is_recv_only(c, id)) {
		return QC_ERR_PROTOCOL_VIOLATION;
	}

	qstream_t *s;
	int err = create_remote_stream(c, id, &s);
	if (err || !s) {
		return err;
	}

	return q_recv_stop(c, s, apperr + QC_ERR_APP_OFFSET);
}

int q_decode_reset(qconnection_t *c, qslice_t *p) {
	uint64_t id;
	if (decode_varint(p, &id) || p->p + 2 > p->e) {
		return QC_ERR_FRAME_ENCODING;
	}
	int apperr = big_16(p->p);
	p->p += 2;
	uint64_t off;
	if (decode_varint(p, &off)) {
		return QC_ERR_FRAME_ENCODING;
	} else if (is_send_only(c, id)) {
		return QC_ERR_PROTOCOL_VIOLATION;
	}

	qstream_t *s;
	int err = create_remote_stream(c, id, &s);
	if (err || !s) {
		return err;
	}

	return q_recv_reset(c, s, apperr + QC_ERR_APP_OFFSET);
}

int q_decode_stream_data(qconnection_t *c, qslice_t *p) {
	uint64_t id, max;
	if (decode_varint(p, &id) || decode_varint(p, &max)) {
		return QC_ERR_FRAME_ENCODING;
	}
	if (is_send_only(c, id)) {
		return QC_ERR_PROTOCOL_VIOLATION;
	}

	qstream_t *s;
	int err = create_stream(c, id, &s);
	if (err || !s) {
		return err;
	}

	s->tx_max = MAX(s->tx_max, max);
	return 0;
}

int q_decode_max_id(qconnection_t *c, qslice_t *p) {
	uint64_t id;
	if (decode_varint(p, &id)) {
		return QC_ERR_FRAME_ENCODING;
	}
	int uni = (id & 1);
	uint64_t *pmax = &c->max_stream_id[(uni << 1) | (c->is_client ? STREAM_SERVER : STREAM_CLIENT)];
	*pmax = MAX(*pmax, id >> 1);
	return 0;
}

int q_decode_max_data(qconnection_t *c, qslice_t *p) {
	uint64_t max;
	if (decode_varint(p, &max)) {
		return QC_ERR_FRAME_ENCODING;
	}
	c->tx_max_data = MAX(max, c->tx_max_data);
	return 0;
}

int q_encode_max_data(qconnection_t *c, qslice_t *p, qtx_packet_t *pkt) {
	// send in every packet for now
	*(p->p++) = MAX_DATA;
	p->p = encode_varint(p->p, c->rx_max_data);
	pkt->flags |= QTX_PKT_MAX_DATA;
	return 0;
}

void q_ack_max_data(qconnection_t *c, const qtx_packet_t *pkt) {
}

void q_lost_max_data(qconnection_t *c, const qtx_packet_t *pkt) {
}

int q_encode_max_id(qconnection_t *c, qslice_t *p, qtx_packet_t *pkt) {
	// send in every packet for now
	*(p->p++) = MAX_STREAM_ID;
	p->p = encode_varint(p->p, c->max_stream_id[STREAM_UNI | (c->is_client ? STREAM_SERVER : STREAM_CLIENT)] >> 1);
	*(p->p++) = MAX_STREAM_ID;
	p->p = encode_varint(p->p, c->max_stream_id[STREAM_UNI | (c->is_client ? STREAM_SERVER : STREAM_CLIENT)] >> 1);
	pkt->flags |= QTX_PKT_MAX_ID_BIDI | QTX_PKT_MAX_ID_UNI;
	return 0;
}

void q_ack_max_id(qconnection_t *c, const qtx_packet_t *pkt) {
}

void q_lost_max_id(qconnection_t *c, const qtx_packet_t *pkt) {
}





