#pragma once
#include "common.h"
#include "cipher.h"
#include <cutils/rbtree.h>

typedef struct qtx_stream qtx_stream_t;
struct qtx_stream {
	// sorting
	rbnode rb;
	int64_t id;

	// buffer management
	bool finished;
	uint64_t have;
	uint64_t sent;
	char *buffer;
	size_t bufsz;

	// flow control
	uint64_t max_allowed;
	uint64_t max_sent;
};

void qtx_set_buffer(qtx_stream_t *t, void *buf, size_t sz);

void *qtx_buffer(qtx_stream_t *t, size_t *psz);
static inline void qtx_consume(qtx_stream_t *t, size_t sz) {t->have += sz;}
static inline void qtx_finish(qtx_stream_t *t) { t->finished = true; }

