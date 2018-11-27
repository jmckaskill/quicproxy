#include "internal.h"

void q_send_close(qconnection_t *c, tick_t now) {
	struct short_packet sp = {
		.ignore_cwnd = true,
		.ignore_closing = true,
		.send_close = true,
		.close_errnum = c->close_errnum,
		.send_ack = true,
	};
	q_send_short_packet(c, &sp, &now);
}

static void free_streams(qconnection_t *c) {
	if ((*c->iface)->free_stream) {
		for (int i = 0; i < 4; i++) {
			for (rbnode *n = rb_begin(&c->rx_streams[i], RB_LEFT); n != NULL; n = rb_next(n, RB_RIGHT)) {
				qstream_t *s = container_of(n, qstream_t, rxnode);
				(*c->iface)->free_stream(c->iface, s);
			}
		}
		for (int i = 0; i < 2; i++) {
			for (rbnode *n = rb_begin(&c->pending_streams[i], RB_LEFT); n != NULL; n = rb_next(n, RB_RIGHT)) {
				qstream_t *s = container_of(n, qstream_t, rxnode);
				(*c->iface)->free_stream(c->iface, s);
			}
		}
	}
}

void qc_shutdown(qconnection_t *c, int error) {
	if (!c->closing) {
		c->closing = true;
		c->close_errnum = error;
		free_streams(c);
		q_async_shutdown(c);
	}
}

void q_internal_shutdown(qconnection_t *c, int error, tick_t now) {
	if (!c->closing) {
		c->closing = true;
		c->close_errnum = error;
		if ((*c->iface)->shutdown) {
			(*c->iface)->shutdown(c->iface, error);
		}
		free_streams(c);
		q_start_shutdown(c, now);
	}
}

int q_decode_close(qconnection_t *c, uint8_t hdr, qslice_t *s, tick_t rxtime) {
	if (s->p + 2 + 1 > s->e) {
		return QC_ERR_FRAME_ENCODING;
	}
	int errnum = (hdr == APPLICATION_CLOSE ? QC_ERR_APP_OFFSET : 0) + big_16(s->p);
	s->p += 2;
	if (hdr == CONNECTION_CLOSE) {
		s->p++; // frame type
	}
	uint64_t reason_len;
	if (decode_varint(s, &reason_len) || reason_len > (uint64_t)(s->e - s->p)) {
		return QC_ERR_FRAME_ENCODING;
	}
	s->p += reason_len;
	c->draining = true;
	q_internal_shutdown(c, errnum, rxtime);
	return 0;
}

int q_encode_close(qconnection_t *c, qslice_t *s, qtx_packet_t *pkt) {
	if (s->p + 1 + 2 + 1 + 1 > s->e) {
		return -1;
	}

	int errnum = c->close_errnum;
	if (QC_ERR_APP_OFFSET <= errnum && errnum < QC_ERR_APP_END) {
		*(s->p++) = APPLICATION_CLOSE;
		s->p = write_big_16(s->p, (uint16_t)(errnum - QC_ERR_APP_OFFSET));
		*(s->p++) = 0; // reason
	} else if (0 <= errnum && errnum < QC_ERR_QUIC_MAX) {
		*(s->p++) = CONNECTION_CLOSE;
		s->p = write_big_16(s->p, (uint16_t)(errnum));
		*(s->p++) = 0; // frame type
		*(s->p++) = 0; // reason phrase
	} else {
		*(s->p++) = CONNECTION_CLOSE;
		s->p = write_big_16(s->p, QC_ERR_INTERNAL);
		*(s->p++) = 0; // frame type
		*(s->p++) = 0; // reason phrase
	}
	pkt->flags |= QTX_PKT_CLOSE;
	return 0;
}

void q_ack_close(qconnection_t *c) {
	c->draining = true;
}

void q_lost_close(qconnection_t *c, tick_t now) {
	q_send_close(c, now);
}