#include "tx.h"

void qtx_set_buffer(qtx_stream_t *t, void *buf, size_t sz) {
	t->buffer = buf;
	t->bufsz = sz;
}

void *qtx_buffer(qtx_stream_t *t, size_t *psz) {
	size_t tail = (size_t)(t->have % t->bufsz);
	size_t head = (size_t)(t->complete % t->bufsz);
	if (tail < head) {
		*psz = head - tail - 1;
	} else {
		*psz = t->bufsz - tail;
	}
	return t->buffer + tail;
}


