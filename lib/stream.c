#include "stream.h"

void qinit_stream(qstream_t *s, void *txbuf, size_t txlen, void *rxbuf, size_t rxlen) {
	memset(&s->tx_packets, 0, sizeof(s->tx_packets));
	qbuf_init(&s->rx, rxbuf, rxlen); 
	qbuf_init(&s->tx, txbuf, txlen);
	s->rx_end = UINT64_MAX;
	s->tx_next = 0;
	s->flags = 0;
}

ssize_t qrx_received(qstream_t *s, bool fin, uint64_t offset, void *voidp, size_t sz) {
	uint64_t end = offset + sz;
	if (end > qbuf_max(&s->rx)) {
		// flow control error
		return -1;
	} else if (end > s->rx_end) {
		// data past the end
		return -1;
	}

	if (fin) {
		if (s->rx_end == UINT64_MAX) {
			s->rx_end = end;
		} else if (s->rx_end != end) {
			// the stream end has shifted
			return -1;
		}
	}

	return qbuf_insert(&s->rx, offset, voidp, sz);
}

size_t qrx_read(qstream_t *s, void *data, size_t len) {
	uint64_t off = s->rx.head;
	len = qbuf_copy(&s->rx, off, data, len);
	qbuf_mark_invalid(&s->rx, off, len);
	qbuf_consume(&s->rx, off + len);
	return len;
}


void qtx_write(qstream_t *s, const void *data, size_t len) {
	qbuf_insert(&s->tx, s->tx.tail, data, len);
	qbuf_fold(&s->tx);
}

void qtx_lost(qstream_t *s, uint64_t offset, size_t sz) {
	qbuf_mark_valid(&s->tx, offset, sz);
}

void qtx_ack(qstream_t *s, uint64_t offset, size_t sz, uint64_t next) {
	qbuf_mark_invalid(&s->tx, offset, sz);
	if (offset == s->tx.head) {
		qbuf_consume(&s->tx, next);
	}
}


