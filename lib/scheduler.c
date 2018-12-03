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
			int type = (c->is_client ? STREAM_CLIENT : STREAM_SERVER) | (uni ? STREAM_UNI : STREAM_BIDI);
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
		} else if (has_data(s) && !s->data.next) {
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

	if (id < c->next_id[id & 3] || (id & STREAM_SERVER_MASK) == (c->is_client ? STREAM_CLIENT : STREAM_SERVER)) {
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
	p = append(p, c->peer_id + 1, c->peer_id[0]);
	uint8_t *pktnum = p;
	p = encode_packet_number(p, pkts->tx_next);
	uint8_t *enc = p;

	// Connection level frames
	if (!c->handshake_complete) {
		p = encode_client_finished(c, p);
	}
	p = q_encode_ack(pkts, p, now, c->local_cfg->ack_delay_exponent);
	p = q_encode_scheduler(c, p, pkt);
	p = q_encode_migration(c, p, pkt);

	if (!(flags & SEND_IGNORE_CWND) && !q_cwnd_allow(c)) {
		return NULL;
	}

	// Main body of the packet - Stream level data
	int local = c->is_client ? STREAM_CLIENT : STREAM_SERVER;
	int bidi = local | STREAM_BIDI;
	int uni = local | STREAM_UNI;

	if (c->closing) {
		p = q_encode_close(c, p, pkt);

	} else if (c->bidi_pending && c->next_id[bidi] < c->max_id[bidi]) {
		qstream_t *s = container_of(c->bidi_pending, qstream_t, ctrl);
		q_setup_local_stream(c, s, c->next_id[bidi]);
		p = q_encode_stream(c, s, p, e, pkt);

	} else if (c->uni_pending && c->next_id[uni] < c->max_id[uni]) {
		qstream_t *s = container_of(c->uni_pending, qstream_t, ctrl);
		q_setup_local_stream(c, s, c->next_id[uni]);
		p = q_encode_stream(c, s, p, e, pkt);

	} else if (c->data_pending && c->tx_data < c->tx_data_max) {
		qstream_t *s = container_of(c->data_pending, qstream_t, data);
		p = q_encode_stream(c, s, p, e, pkt);

	} else if (c->ctrl_pending) {
		qstream_t *s = container_of(c->ctrl_pending, qstream_t, ctrl);
		p = q_encode_stream(c, s, p, e, pkt);

	} else if (flags & SEND_PING) {
		*(p++) = PING;
	}

	if (!(flags & SEND_EMPTY) && !pkt->stream && pkts->tx_next && !q_pending_scheduler(c) && !q_pending_migration(c)) {
		// No reason to send
		return NULL;
	}

	if (!c->handshake_complete) {
		memset(p, PADDING, (size_t)(e - p));
		p = e;
	}

	p += QUIC_TAG_SIZE;
	write_big_16(pktnum - 2, VARINT_16 | (uint16_t)(p - pktnum));
	c->prot_tx.vtable->encrypt(&c->prot_tx.vtable, pkts->tx_next, buf, (size_t)(enc - buf), enc, p - QUIC_TAG_SIZE);
	c->prot_tx.vtable->protect(&c->prot_tx.vtable, pktnum, (size_t)(enc - pktnum), (size_t)(p - pktnum));

	if ((*c->iface)->send(c->iface, buf, (size_t)(p - buf), (struct sockaddr*)&c->addr, c->addr_len, &pkt->sent)) {
		return NULL;
	}

	if (pkt->flags & QPKT_RETRANSMIT) {
		c->retransmit_packets++;
		q_start_probe_timer(c, pkt->sent);
	}
	cancel_apc(c->dispatcher, &c->tx_timer);
	if (pkt->stream) {
		commit_stream(c, pkt->stream, pkt);
	}
	q_commit_scheduler(c, pkt);
	q_commit_migration(c, pkt);
	q_cwnd_sent(c, pkt);
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

	// flush the new max id through
	if (q_pending_scheduler(c)) {
		q_async_send_data(c);
	}
}

static inline bool is_send_only(struct connection *c, uint64_t id) {
	bool uni = (id & STREAM_UNI_MASK) == STREAM_UNI;
	bool client = (id & STREAM_SERVER_MASK) == STREAM_CLIENT;
	return uni && client == c->is_client;
}

static inline bool is_recv_only(struct connection *c, uint64_t id) {
	bool uni = (id & STREAM_UNI_MASK) == STREAM_UNI;
	bool client = (id & STREAM_SERVER_MASK) == STREAM_CLIENT;
	return uni && client != c->is_client;
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
	int local = (c->is_client ? STREAM_CLIENT : STREAM_SERVER);
	int remote = (c->is_client ? STREAM_SERVER : STREAM_CLIENT);
	c->max_id[STREAM_BIDI | local] = (c->peer_cfg.bidi_streams << 2) | STREAM_BIDI | local;
	c->max_id[STREAM_BIDI | remote] = (c->local_cfg->bidi_streams << 2) | STREAM_BIDI | remote;
	c->max_id[STREAM_UNI | local] = (c->peer_cfg.uni_streams << 2) | STREAM_UNI | local;
	c->max_id[STREAM_UNI | remote] = (c->local_cfg->uni_streams << 2) | STREAM_UNI | remote;
	c->tx_data_max = c->peer_cfg.max_data;
	c->rx_data_max = c->local_cfg->max_data;
}

int q_decode_max_id(struct connection *c, qslice_t *p) {
	uint64_t id;
	if (decode_varint(p, &id)) {
		return QC_ERR_FRAME_ENCODING;
	}
	id = (id << 1) | (c->is_client ? STREAM_CLIENT : STREAM_SERVER);
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

size_t q_scheduler_cwnd_size(const qtx_packet_t *pkt) {
	size_t ret = 0;
	if (pkt->flags & QPKT_MAX_DATA) {
		ret += 1 + 4;
	}
	if (pkt->flags & QPKT_MAX_ID_UNI) {
		ret += 1 + 4;
	}
	if (pkt->flags & QPKT_MAX_ID_BIDI) {
		ret += 1 + 4;
	}
	return ret;
}

static uint64_t rx_max_data(struct connection *c) {
	return c->rx_data + c->local_cfg->max_data;
}

static uint64_t max_id(struct connection *c, int uni) {
	int remote = (c->is_client ? STREAM_SERVER : STREAM_CLIENT);
	int type = uni | remote;
	return c->next_id[type] + 4 * ((uni ? c->local_cfg->uni_streams : c->local_cfg->bidi_streams) - c->rx_streams[type].size);
}

bool q_pending_scheduler(struct connection *c) {
	int remote = (c->is_client ? STREAM_SERVER : STREAM_CLIENT);
	return rx_max_data(c) > c->rx_data_max
		|| max_id(c, STREAM_UNI) > c->max_id[remote | STREAM_UNI]
		|| max_id(c, STREAM_BIDI) > c->max_id[remote | STREAM_BIDI];
}

uint8_t *q_encode_scheduler(struct connection *c, uint8_t *p, qtx_packet_t *pkt) {
	// MAX_DATA
	if (rx_max_data(c) > c->rx_data_max) {
		*(p++) = MAX_DATA;
		p = encode_varint(p, rx_max_data(c));
		pkt->flags |= QPKT_MAX_DATA;
	}

	// Max Stream IDs
	int remote = (c->is_client ? STREAM_SERVER : STREAM_CLIENT);
	int uni = STREAM_UNI | remote;
	int bidi = STREAM_BIDI | remote;
	if (max_id(c, STREAM_UNI) > c->max_id[uni]) {
		*(p++) = MAX_STREAM_ID;
		p = encode_varint(p, (max_id(c, STREAM_UNI) << 1));
		pkt->flags |= QPKT_MAX_ID_UNI;
	}
	if (max_id(c, STREAM_BIDI) > c->max_id[bidi]) {
		*(p++) = MAX_STREAM_ID;
		p = encode_varint(p, (max_id(c, STREAM_BIDI) << 1));
		pkt->flags |= QPKT_MAX_ID_BIDI;
	}
	return p;
}

void q_commit_scheduler(struct connection *c, const qtx_packet_t *pkt) {
	if (pkt->flags & QPKT_MAX_DATA) {
		c->rx_data_max = rx_max_data(c);
	}
	int remote = (c->is_client ? STREAM_SERVER : STREAM_CLIENT);
	if (pkt->flags & QPKT_MAX_ID_UNI) {
		c->max_id[remote | STREAM_UNI] = max_id(c, STREAM_UNI);
	}
	if (pkt->flags & QPKT_MAX_ID_BIDI) {
		c->max_id[remote | STREAM_BIDI] = max_id(c, STREAM_BIDI);
	}
}






