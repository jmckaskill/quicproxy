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

typedef struct qtx_packet qtx_packet_t;
struct qtx_packet {
	uint64_t off;
	size_t len;
	qtx_stream_t *stream;
	tick_t sent;
};

typedef struct qpacket_buffer qpacket_buffer_t;
struct qpacket_buffer {
	qtx_packet_t *sent;	// packets sent for retries
	size_t sent_len;	// number of packets in the send buffer
	uint64_t received;	// receive bitset - one bit per packet
	uint64_t rx_next;   // next packet to receive (highest received + 1)
	uint64_t tx_next;   // next packet to send (highest sent + 1)
	qkeyset_t tkey;
	qkeyset_t rkey;
};

