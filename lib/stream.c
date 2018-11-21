#include "stream.h"

void qinit_stream(qstream_t *s, void *txbuf, size_t txlen, void *rxbuf, size_t rxlen) {
	qbuf_init(&s->rx, false, rxbuf, rxlen); 
	qbuf_init(&s->tx, true, txbuf, txlen);
	s->rx_end = UINT64_MAX;
	s->tx_next = 0;
	s->tail_ptr = NULL;
	s->tail_size = 0;
	s->flags = 0;
}

int qrx_received(qstream_t *s, bool fin, uint64_t offset, void *voidp, size_t sz) {
	char *p = voidp;

	uint64_t end = offset + sz;
	if (end <= s->rx.tail) {
		// old data
		return QRX_WAIT;
	} else if (end > qrx_max(s)) {
		// flow control error
		return QRX_FLOW_CONTROL;
	} else if (end > s->rx_end) {
		// data past the end
		return QRX_EOF;
	}

	if (fin) {
		if (s->rx_end == UINT64_MAX) {
			s->rx_end = end;
		} else if (s->rx_end != end) {
			// the stream end has shifted
			return QRX_EOF;
		}
	}

	if (offset < s->rx.tail) {
		// old start, but runs into new territory
		size_t shift = (size_t)(s->rx.tail - offset);
		p += shift;
		sz -= shift;
		offset = s->rx.tail;
	}

	if (offset == s->rx.tail) {
		s->tail_ptr = p;
		s->tail_size = sz;
		return QRX_HAVE_DATA;
	} else {
		qbuf_insert(&s->rx, offset, sz, p);
		return QRX_WAIT;
	}
}

void qrx_fold(qstream_t *s) {
	if (s->tail_size) {
		qbuf_insert(&s->rx, s->rx.tail, s->tail_size, s->tail_ptr);
		s->tail_ptr = NULL;
		s->tail_size = 0;
	}
}

uint64_t qrx_max(qstream_t *s) {
	return s->rx.head + s->rx.size - 1;
}

size_t qtx_in_flight(qstream_t *s) {
	return s->tx.size - (size_t)(s->tx.head - s->tx.tail);
}

ssize_t qrx_buffer(qstream_t *s, void **pdata) {
	if (s->rx.head < s->rx.tail) {
		return qbuf_buffer(&s->rx, pdata);
	} else if (s->tail_size) {
		*pdata = s->tail_ptr;
		return s->tail_size;
	} else if (s->rx.tail == s->rx_end) {
		return QRX_EOF;
	} else {
		return QRX_WAIT;
	}
}

ssize_t qrx_read(qstream_t *s, void *buf, size_t sz) {
	size_t ret = 0;
	void *src;
	size_t have;

	while ((have = qrx_buffer(s, &src)) > 0) {
		if (ret + have > sz) {
			memcpy((char*)buf + ret, src, sz - ret);
			qrx_consume(s, sz - ret);
			return sz;
		} else {
			memcpy((char*)buf + ret, src, have);
			qrx_consume(s, have);
			ret += have;
		}
	}

	if (ret) {
		return ret;
	} else if (s->rx.tail == s->rx_end) {
		return QRX_EOF;
	} else {
		return QRX_WAIT;
	}
}

void qrx_consume(qstream_t *s, size_t sz) {
	if (s->rx.head == s->rx.tail) {
		assert(sz <= s->tail_size);
		s->tail_size -= sz;
		s->tail_ptr += sz;
	} else {
#ifdef DEBUG
		uint64_t off;
		size_t have;
		qbuf_buffer(&s->rx, &off, &have);
		assert(sz <= have);
#endif
		qbuf_consume(&s->rx, sz);
	}
}

size_t qtx_write(qstream_t *s, const void *buf, size_t sz) {
	assert(!(s->flags & (QSTREAM_END | QSTREAM_RESET)));
	size_t ret = 0;
	while (ret < sz) {
		void *tgt;
		size_t have = qbuf_buffer(&s->tx, &tgt);
		if (!have) {
			break;
		} else if (ret + have > sz) {
			have = sz - ret;
		}
		memcpy(tgt, (char*)buf + ret, have);
		qbuf_consume(&s->tx, have);
		ret += have;
	}
	return ret;
}

