#include "internal.h"

void q_send_close(struct connection *c, tick_t now) {
	q_send_packet(c, now, SEND_IGNORE_CWND | SEND_EMPTY);
}

void qc_shutdown(qconnection_t *cin, int error) {
	struct connection *c = (struct connection*)cin;
	if (!c->closing) {
		c->closing = true;
		c->close_errnum = error;
		q_free_streams(c);
		q_async_shutdown(c);
	}
}

void q_internal_shutdown(struct connection *c, int error, tick_t now) {
	if (!c->closing) {
		c->closing = true;
		c->close_errnum = error;
		if ((*c->iface)->shutdown) {
			(*c->iface)->shutdown(c->iface, error);
		}
		q_free_streams(c);
		q_start_shutdown(c, now);
	}
}

int q_decode_close(struct connection *c, uint8_t hdr, qslice_t *s, tick_t rxtime) {
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

uint8_t *q_encode_close(struct connection *c, uint8_t *p, qtx_packet_t *pkt) {
	int errnum = c->close_errnum;
	if (QC_ERR_APP_OFFSET <= errnum && errnum < QC_ERR_APP_END) {
		*(p++) = APPLICATION_CLOSE;
		p = write_big_16(p, (uint16_t)(errnum - QC_ERR_APP_OFFSET));
		*(p++) = 0; // reason
	} else if (0 <= errnum && errnum < QC_ERR_QUIC_MAX) {
		*(p++) = CONNECTION_CLOSE;
		p = write_big_16(p, (uint16_t)(errnum));
		*(p++) = 0; // frame type
		*(p++) = 0; // reason phrase
	} else {
		*(p++) = CONNECTION_CLOSE;
		p = write_big_16(p, QC_ERR_INTERNAL);
		*(p++) = 0; // frame type
		*(p++) = 0; // reason phrase
	}
	pkt->flags |= QPKT_CLOSE;
	return p;
}

void q_ack_close(struct connection *c) {
	c->draining = true;
}

void q_lost_close(struct connection *c, tick_t now) {
	q_send_close(c, now);
}
