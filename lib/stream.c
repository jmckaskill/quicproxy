#include "stream.h"

void qinit_stream(qstream_t *s, void *txbuf, size_t txlen, void *rxbuf, size_t rxlen) {
	memset(s, 0, sizeof(*s));
	qbuf_init(&s->rx, rxbuf, rxlen); 
	qbuf_init(&s->tx, txbuf, txlen);
	s->id = UINT64_MAX;
	s->rx_end = UINT64_MAX;
	s->flags = QSTREAM_NEW;
	if (!s->rx.size) {
		s->flags |= QRX_COMPLETE;
	}
}

ssize_t qrx_received(qstream_t *s, bool fin, uint64_t offset, void *voidp, size_t sz) {
	uint64_t end = offset + sz;
	if (end > qbuf_max(&s->rx)) {
		// flow control error
		return -1;
	} else if (end > s->rx_end) {
		// data past the end
		return -1;
	} else if (s->flags & (QTX_STOP | QRX_RST | QRX_COMPLETE)) {
		return 0;
	}

	if (fin) {
		if (s->rx_end == UINT64_MAX) {
			s->rx_end = end;
			s->flags |= QRX_FIN;
		} else if (s->rx_end != end) {
			// the stream end has shifted
			return -1;
		}
	}


	size_t ret = qbuf_insert(&s->rx, offset, voidp, sz);
	if (ret && s->rx.tail == s->rx_end) {
		s->flags |= QRX_COMPLETE;
	}
	return ret;
}

void qrx_stop(qstream_t *s) {
	if (!(s->flags & QTX_STOP)) {
		s->flags |= QRX_COMPLETE | QTX_STOP | QTX_DIRTY;
		qbuf_init(&s->rx, NULL, 0);
	}
}

size_t qrx_read(qstream_t *s, void *data, size_t len) {
	if (s->flags & (QRX_RST | QTX_STOP | QRX_COMPLETE)) {
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
		s->tx_errnum = errnum;
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

void qtx_lost(qstream_t *s, uint64_t offset, size_t sz) {
	if (!(s->flags & QTX_RST)) {
		qbuf_mark_valid(&s->tx, offset, sz);
	}
}

void qtx_ack(qstream_t *s, uint64_t offset, size_t sz, uint64_t next) {
	if (!(s->flags & QTX_RST)) {
		qbuf_mark_invalid(&s->tx, offset, sz);
		if (offset == s->tx.head) {
			qbuf_consume(&s->tx, next);
			if (qtx_eof(s, s->tx.head)) {
				s->flags |= QRX_DATA_ACK;
			}
		}
	}
}


