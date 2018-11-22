#pragma once
#include "common.h"
#include "buffer.h"
#include <cutils/rbtree.h>

#define QSTREAM_END 1
#define QSTREAM_RESET 2
#define QSTREAM_END_SENT 4
#define QSTREAM_RESET_SENT 8
#define QSTREAM_TX_COMPLETE 16
#define STREAM_MAX UINT64_C(0x4000000000000000)

typedef struct qstream qstream_t;
struct qstream {
	rbnode rb;
	qstream_t *next, *prev;
	int64_t id;

	qbuffer_t rx;
	qbuffer_t tx;

	uint64_t rx_end;	// full stream size - UINT64_MAX until we see a fin
	uint64_t tx_next;	// next byte to send
	uint64_t tx_max;    // flow control max

	uint8_t flags;
};

// For functions returning ssize_t
#define QRX_FLOW_CONTROL -2
#define QRX_WAIT -1
#define QRX_EOF 0
// +ve - how much data has been added

void qinit_stream(qstream_t *s, void *txbuf, size_t txlen, void *rxbuf, size_t rxlen);

static inline uint64_t qrx_offset(qstream_t *s) {return s->rx.head;}
static inline bool qrx_eof(qstream_t *s) {return s->rx.head == s->rx_end;}

// These are used by the quic transport library
// append data, the stream may continue to use the provided buffer until the next call to fold
ssize_t qrx_received(qstream_t *s, bool fin, uint64_t offset, void *p, size_t sz);
static inline void qrx_fold(qstream_t *s) {qbuf_fold(&s->rx);}

static inline void qtx_set_finish(qstream_t *s) {s->flags |= QSTREAM_END;}
static inline void qtx_set_reset(qstream_t *s) {s->flags |= QSTREAM_RESET;}
bool qtx_can_send(qstream_t *s);

static inline size_t qrx_read(qstream_t *s, void *data, size_t len) {
	uint64_t off = s->rx.head;
	size_t ret = qbuf_copy(&s->rx, off, data, len);
	qbuf_remove(&s->rx, off, ret);
	return ret;
}

static inline void qtx_write(qstream_t *s, const void *data, size_t len) {
	qbuf_insert(&s->tx, s->tx.tail, data, len);
	qbuf_fold(&s->tx);
}


