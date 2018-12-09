#include "internal.h"

static void notify_app(struct connection *c, int error) {
	if ((*c->iface)->shutdown) {
		(*c->iface)->shutdown(c->iface, error);
	}
}

// Four forms of shutdown
// 1. From application
// 2. From library
// 3. From remote
// 4. From idle timeout

void qc_shutdown(qconnection_t *cin, int error) {
	struct connection *c = (struct connection*)cin;
	if (!(c->flags & QC_CLOSING)) {
		c->flags |= QC_CLOSING;
		c->close_errnum = error;
		q_start_shutdown(c);
		q_send_close(c);
		q_free_streams(c);
	}
}

void q_shutdown_from_library(struct connection *c, int error) {
	if (!(c->flags & QC_CLOSING)) {
		c->flags |= QC_CLOSING;
		c->close_errnum = error;
		q_start_shutdown(c);
		q_send_close(c);
		q_free_streams(c);
		notify_app(c, error);
	}
}

void q_shutdown_from_idle(struct connection *c) {
	c->flags |= QC_CLOSING | QC_DRAINING;
	c->close_errnum = 0;
	q_start_shutdown(c);
	q_free_streams(c);
	notify_app(c, QC_ERR_IDLE_TIMEOUT);
}

static void shutdown_from_remote(struct connection *c, int error) {
	// we're allowed to send one close frame to ack the remote
	// after that point we are in draining and are not allowed to send anything
	c->flags |= QC_CLOSING;
	c->close_errnum = 0;
	q_start_shutdown(c);
	q_send_close(c);
	c->flags |= QC_DRAINING;
	q_free_streams(c);
	notify_app(c, error);
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
	if (q_decode_varint(s, &reason_len) || reason_len > (uint64_t)(s->e - s->p)) {
		return QC_ERR_FRAME_ENCODING;
	}
	s->p += reason_len;
	if (c->flags & QC_CLOSING) {
		c->flags |= QC_DRAINING; // remote is confirming our shutdown request
	} else {
		shutdown_from_remote(c, errnum);
	}
	return 0;
}

uint8_t *q_encode_close(struct connection *c, uint8_t *p, uint8_t *e, bool pad) {
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
	// pad out the message to make sure it goes through
	return pad ? append_bytes(p, 0, (size_t)(e - p)) : p;
}

