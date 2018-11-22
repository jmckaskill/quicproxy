#include "stream.h"

void qinit_stream(qstream_t *s, void *txbuf, size_t txlen, void *rxbuf, size_t rxlen) {
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

bool qtx_can_send(qstream_t *s) {
	return (s->tx_next < s->tx.tail)
		|| ((s->flags & QSTREAM_END) && !(s->flags & QSTREAM_END_SENT))
		|| ((s->flags & QSTREAM_RESET) && !(s->flags & QSTREAM_RESET_SENT));
}

