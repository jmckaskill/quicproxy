#include "internal.h"
#include "connection.h"

static void enqueue(struct qstream_list **head, struct qstream_list *node) {
	assert(!node->next && !node->prev);
	if (*head) {
		node->next = *head;
		node->prev = (*head)->prev;
		node->next->prev = node;
		node->prev->next = node;
	} else {
		node->next = node;
		node->prev = node;
		*head = node;
	}
}

static struct qstream_list *remove_head(struct qstream_list **head) {
	struct qstream_list *n = *head;
	*head = n->next;
	n->next->prev = n->prev;
	n->prev->next = n->next;
	n->next = NULL;
	n->prev = NULL;
	return n;
}

static void dequeue(struct qstream_list **head, struct qstream_list *node) {
	assert(node->next && node->prev);
	node->next->prev = node->prev;
	node->prev->next = node->next;
	node->next = NULL;
	node->prev = NULL;
	if (*head == node) {
		*head = node->next;
	}
}

static bool has_data(qstream_t *s) {
	return s->tx_next < s->tx_max_allowed && s->tx_next < s->tx.tail;
}

void qc_flush(qconnection_t *cin, qstream_t *s) {
	struct connection *c = (struct connection*)cin;
	if (c->closing) {
		return;
	}

	if (s->id == UINT64_MAX) {
		if (!s->ctrl.next) {
			bool uni = (s->rx.size == 0);
			enqueue(uni ? &c->uni_pending : &c->bidi_pending, &s->ctrl);
			int type = (uni ? STREAM_UNI : STREAM_BIDI) | c->is_server;
			if (q_cwnd_allow(c) && c->next_id[type] < c->max_id[type]) {
				q_async_send_data(c);
			}
		}
	} else {
		if ((s->flags & QS_TX_CONTROL) && !s->ctrl.next) {
			enqueue(&c->ctrl_pending, &s->ctrl);
			if (q_cwnd_allow(c)) {
				q_async_send_data(c);
			}
		} 
		if (has_data(s) && !s->data.next) {
			enqueue(&c->data_pending, &s->data);
			if (q_cwnd_allow(c) && c->tx_data < c->tx_data_max) {
				q_async_send_data(c);
			}
		}
	}
}

static void commit_stream(struct connection *c, qstream_t *s, qtx_packet_t *pkt) {
	q_commit_stream(c, s, pkt);

	int type = s->id & 3;
	if (s->id == c->next_id[type]) {
		c->next_id[type] += 4;
		rb_insert(&c->rx_streams[type], rb_begin(&c->rx_streams[type], RB_RIGHT), &s->rxnode, RB_RIGHT);
		dequeue((s->id & STREAM_UNI_MASK) == STREAM_UNI ? &c->uni_pending : &c->bidi_pending, &s->ctrl);
	}

	if (has_data(s) && !s->data.next) {
		enqueue(&c->data_pending, &s->data);
	} else if (!has_data(s) && s->data.next) {
		dequeue(&c->data_pending, &s->data);
	} else if (c->data_pending == &s->data) {
		c->data_pending = s->data.next;
	}

	if (s->ctrl.next) {
		dequeue(&c->ctrl_pending, &s->ctrl);
	}
}

static qstream_t *find_stream(struct connection *c, uint64_t id) {
	rbnode *n = c->rx_streams[id & 3].root;
	while (n) {
		qstream_t *s = container_of(n, qstream_t, rxnode);
		if (s->id == id) {
			return s;
		}
		n = (id < s->id) ? n->child[RB_LEFT] : n->child[RB_RIGHT];
	}
	return NULL;
}

static int create_remote_stream(struct connection *c, uint64_t id, qstream_t **ps) {
	*ps = NULL;

	if ((id >> 2) >= c->max_id[id & 3]) {
		return QC_ERR_STREAM_ID;
	} else if (c->closing) {
		return 0;
	} else if ((*ps = find_stream(c, id)) != NULL) {
		return 0;
	}

	if (id < c->next_id[id & 3] || (id & STREAM_SERVER_MASK) == c->is_server) {
		// this must be an out of order frame from an old stream
		// we already closed
		return 0;
	}

	if (!(*c->iface)->new_stream) {
		return QC_ERR_INTERNAL;
	}

	// now we need to create the stream (and all the intermediate streams)
	bool uni = (id & STREAM_UNI_MASK) == STREAM_UNI;
	rbnode *prev = rb_begin(&c->rx_streams[id & 3], RB_RIGHT);
	while (c->next_id[id & 3] <= id) {
		qstream_t *s = (*c->iface)->new_stream(c->iface, uni);
		if (!s) {
			return QC_ERR_INTERNAL;
		}
		*ps = s;
		q_setup_remote_stream(c, s, c->next_id[id & 3]);
		rb_insert(&c->rx_streams[id & 3], prev, &s->rxnode, RB_RIGHT);
		prev = &s->rxnode;
		c->next_id[id & 3] += 4;

		qc_flush((qconnection_t*)c, s);
	}
	return 0;
}

void q_free_streams(struct connection *c) {
	if ((*c->iface)->free_stream) {
		for (int i = 0; i < 4; i++) {
			for (rbnode *n = rb_begin(&c->rx_streams[i], RB_LEFT); n != NULL; n = rb_next(n, RB_RIGHT)) {
				qstream_t *s = container_of(n, qstream_t, rxnode);
				(*c->iface)->free_stream(c->iface, s);
			}
		}
		while (c->uni_pending) {
			qstream_t *s = container_of(remove_head(&c->uni_pending), qstream_t, ctrl);
			(*c->iface)->free_stream(c->iface, s);
		}
		while (c->bidi_pending) {
			qstream_t *s = container_of(remove_head(&c->bidi_pending), qstream_t, ctrl);
			(*c->iface)->free_stream(c->iface, s);
		}
	}
}

qtx_packet_t *q_send_packet(struct connection *c, tick_t now, uint8_t flags) {
	qpacket_buffer_t *pkts = &c->prot_pkts;
	if (!c->peer_verified || pkts->tx_next == pkts->tx_oldest + pkts->sent_len || c->draining) {
		return NULL;
	}

	uint8_t buf[DEFAULT_PACKET_SIZE], *p = buf;
	uint8_t *e = p + sizeof(buf) - QUIC_TAG_SIZE;

	qtx_packet_t *pkt = &pkts->sent[pkts->tx_next % pkts->sent_len];
	memset(pkt, 0, sizeof(*pkt));

	// Header
	*(p++) = SHORT_PACKET;
	p = append(p, c->peer_id, c->peer_len);
	uint8_t *pktnum = p;
	p = encode_packet_number(p, pkts->tx_largest_acked, pkts->tx_next);
	uint8_t *enc = p;

	// Connection level frames
	if (!c->handshake_complete) {
		p = encode_client_finished(c, p);
	}
	p = q_encode_ack(pkts, p, now, c->local_cfg->ack_delay_exponent);
	p = q_encode_scheduler(c, p, pkt);
	p = q_encode_migration(c, p, pkt);

	// Debugging congestion window
	*(p++) = STREAM_BLOCKED;
	p = encode_varint(p, c->bytes_in_flight);
	p = encode_varint(p, c->congestion_window);

	if ((flags & SEND_FORCE) || !pkts->tx_next) {
		pkt->flags |= QPKT_SEND;
	} else if (!q_cwnd_allow(c)) {
		return NULL;
	}

	// Main body of the packet - Stream level data
	int local_bidi = c->is_server | STREAM_BIDI;
	int local_uni = c->is_server | STREAM_UNI;
	bool pad = !c->handshake_complete;

	if (c->closing) {
		p = q_encode_close(c, p, pkt);

	} else if (c->bidi_pending && c->next_id[local_bidi] < c->max_id[local_bidi]) {
		qstream_t *s = container_of(c->bidi_pending, qstream_t, ctrl);
		q_setup_local_stream(c, s, c->next_id[local_bidi]);
		p = q_encode_stream(c, s, p, e, pkt, pad);

	} else if (c->uni_pending && c->next_id[local_uni] < c->max_id[local_uni]) {
		qstream_t *s = container_of(c->uni_pending, qstream_t, ctrl);
		q_setup_local_stream(c, s, c->next_id[local_uni]);
		p = q_encode_stream(c, s, p, e, pkt, pad);

	} else if (c->data_pending && c->tx_data < c->tx_data_max) {
		qstream_t *s = container_of(c->data_pending, qstream_t, data);
		p = q_encode_stream(c, s, p, e, pkt, pad);

	} else if (c->ctrl_pending) {
		qstream_t *s = container_of(c->ctrl_pending, qstream_t, ctrl);
		p = q_encode_stream(c, s, p, e, pkt, pad);

	} else if (flags & SEND_PING) {
		*(p++) = PING;
	}

	if (!(pkt->flags & QPKT_SEND)) {
		// No reason to send
		return NULL;
	}

	c->prot_tx.vtable->encrypt(&c->prot_tx.vtable, pkts->tx_next, buf, (size_t)(enc - buf), enc, p);
	p += QUIC_TAG_SIZE;
	c->prot_tx.vtable->protect(&c->prot_tx.vtable, pktnum, (size_t)(enc - pktnum), (size_t)(p - pktnum));

	if ((*c->iface)->send(c->iface, buf, (size_t)(p - buf), (struct sockaddr*)&c->addr, c->addr_len, &pkt->sent)) {
		return NULL;
	}
	if (q_cwnd_sent(c, pkt)) {
		// this has non ack content
		pkt->flags |= QPKT_CWND;
		q_reset_rx_timer(c, pkt->sent);
	}
	if (pkt->stream) {
		commit_stream(c, pkt->stream, pkt);
	}
	q_commit_scheduler(c, pkt);
	q_commit_migration(c, pkt);
	q_commit_close(c, pkt);
	cancel_apc(c->dispatcher, &c->ack_timer);
	pkts->tx_next++;
	return pkt;
}


void q_remove_stream(struct connection *c, qstream_t *s) {
	assert(s->id != UINT64_MAX);
	assert(!s->ctrl.next);
	assert(!s->data.next);
	rb_remove(&c->rx_streams[s->id & 3], &s->rxnode);

	for (rbnode *n = rb_begin(&s->packets, RB_LEFT); n != NULL; n = rb_next(n, RB_RIGHT)) {
		qtx_packet_t *pkt = container_of(n, qtx_packet_t, rb);
		assert(pkt->off != UINT64_MAX);
		pkt->stream = NULL;
		pkt->off = 0;
		pkt->len = 0;
	}

	if ((*c->iface)->free_stream) {
		(*c->iface)->free_stream(c->iface, s);
	}

	// Don't force a new flush to send the max ID through.
	// Instead wait for already sent data or the ack timer.
}

static inline bool is_send_only(struct connection *c, uint64_t id) {
	return (id & STREAM_UNI_MASK) && (id & STREAM_SERVER_MASK) == c->is_server;
}

static inline bool is_recv_only(struct connection *c, uint64_t id) {
	return (id & STREAM_UNI_MASK) && (id & STREAM_SERVER_MASK) == !c->is_server;
}

int q_decode_stream(struct connection *c, uint8_t hdr, qslice_t *p) {
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
	} else if (is_send_only(c, id)) {
		return QC_ERR_PROTOCOL_VIOLATION;
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

int q_decode_stop(struct connection *c, qslice_t *p) {
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

int q_decode_reset(struct connection *c, qslice_t *p) {
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

	return q_recv_reset(c, s, apperr + QC_ERR_APP_OFFSET, off);
}

int q_decode_stream_data(struct connection *c, qslice_t *p) {
	uint64_t id, max;
	if (decode_varint(p, &id) || decode_varint(p, &max)) {
		return QC_ERR_FRAME_ENCODING;
	}
	if (is_recv_only(c, id)) {
		return QC_ERR_PROTOCOL_VIOLATION;
	}

	qstream_t *s;
	int err = create_remote_stream(c, id, &s);
	if (err || !s) {
		return err;
	}

	return q_recv_max_stream(c, s, max);
}

void q_update_scheduler_from_cfg(struct connection *c) {
	c->max_id[STREAM_BIDI |  c->is_server] = (c->peer_cfg.bidi_streams << 2)   | STREAM_BIDI |  c->is_server;
	c->max_id[STREAM_BIDI | !c->is_server] = (c->local_cfg->bidi_streams << 2) | STREAM_BIDI | !c->is_server;
	c->max_id[STREAM_UNI  |  c->is_server] = (c->peer_cfg.uni_streams << 2)    | STREAM_UNI  |  c->is_server;
	c->max_id[STREAM_UNI  | !c->is_server] = (c->local_cfg->uni_streams << 2)  | STREAM_UNI  | !c->is_server;
	c->tx_data_max = c->peer_cfg.max_data;
	c->rx_data_max = c->local_cfg->max_data;
}

int q_decode_max_id(struct connection *c, qslice_t *p) {
	uint64_t id;
	if (decode_varint(p, &id)) {
		return QC_ERR_FRAME_ENCODING;
	}
	id = (id << 1) | c->is_server;
	if (id <= c->max_id[id & 3]) {
		return 0;
	}
	if (q_cwnd_allow(c) && c->next_id[id & 3] == c->max_id[id & 3] && ((id & STREAM_UNI) ? c->uni_pending : c->bidi_pending)) {
		q_async_send_data(c);
	}
	c->max_id[id & 3] = id;
	return 0;
}

int q_decode_max_data(struct connection *c, qslice_t *p) {
	uint64_t max;
	if (decode_varint(p, &max)) {
		return QC_ERR_FRAME_ENCODING;
	}
	if (max <= c->tx_data_max) {
		return 0;
	}
	if (q_cwnd_allow(c) && c->data_pending) {
		q_async_send_data(c);
	}
	c->tx_data_max = max;
	return 0;
}

static uint64_t rx_max_data(struct connection *c) {
	return c->rx_data + c->local_cfg->max_data;
}

static uint64_t max_id(struct connection *c, int type) {
	uint64_t max_concurrent = (type & STREAM_UNI_MASK) ? c->local_cfg->uni_streams : c->local_cfg->bidi_streams;
	return c->next_id[type] + 4 * (max_concurrent - c->rx_streams[type].size);
}

uint8_t *q_encode_scheduler(struct connection *c, uint8_t *p, qtx_packet_t *pkt) {
	// MAX_DATA
	if (rx_max_data(c) > c->rx_data_max) {
		*(p++) = MAX_DATA;
		p = encode_varint(p, rx_max_data(c));
		pkt->flags |= QPKT_MAX_DATA | QPKT_SEND;
	}

	// Max Stream IDs
	int uni = STREAM_UNI | !c->is_server;
	int bidi = STREAM_BIDI | !c->is_server;
	if (max_id(c, uni) > c->max_id[uni]) {
		*(p++) = MAX_STREAM_ID;
		p = encode_varint(p, (max_id(c, uni) << 1));
		pkt->flags |= QPKT_MAX_ID_UNI | QPKT_SEND;
	}
	if (max_id(c, bidi) > c->max_id[bidi]) {
		*(p++) = MAX_STREAM_ID;
		p = encode_varint(p, (max_id(c, bidi) << 1));
		pkt->flags |= QPKT_MAX_ID_BIDI | QPKT_SEND;
	}
	return p;
}

void q_commit_scheduler(struct connection *c, const qtx_packet_t *pkt) {
	if (pkt->flags & QPKT_MAX_DATA) {
		c->rx_data_max = rx_max_data(c);
	}
	if (pkt->flags & QPKT_MAX_ID_UNI) {
		int uni = STREAM_UNI | !c->is_server;
		c->max_id[uni] = max_id(c, uni);
	}
	if (pkt->flags & QPKT_MAX_ID_BIDI) {
		int bidi = STREAM_BIDI | !c->is_server;
		c->max_id[bidi] = max_id(c, bidi);
	}
}






