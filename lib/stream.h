#pragma once
#include "common.h"
#include "buffer.h"
#include <cutils/rbtree.h>

#define QSTREAM_END 1
#define QSTREAM_RESET 2
#define QSTREAM_IN_TX_QUEUE 4
#define QSTREAM_TX_COMPLETE 16
#define STREAM_MAX UINT64_C(0x4000000000000000)

typedef struct qstream qstream_t;
struct qstream {
	rbnode rxnode;
	rbnode txnode;
	uint64_t id;

	qbuffer_t rx;
	qbuffer_t tx;

	uint64_t rx_end;	// full stream size - UINT64_MAX until we see a fin
	uint64_t tx_next;	// next byte to send
	uint64_t tx_max;    // flow control max

	rbtree tx_packets;
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
static inline bool qtx_eof(qstream_t *s, uint64_t off) {return off == s->tx.tail && (s->flags & QSTREAM_END);}

// These are used by the quic transport library
// append data, the stream may continue to use the provided buffer until the next call to fold
ssize_t qrx_received(qstream_t *s, bool fin, uint64_t offset, void *p, size_t sz);
static inline void qrx_fold(qstream_t *s) {qbuf_fold(&s->rx);}
void qtx_ack(qstream_t *s, uint64_t offset, size_t sz, uint64_t next);
void qtx_lost(qstream_t *s, uint64_t offset, size_t sz);

static inline void qtx_set_finish(qstream_t *s) {s->flags |= QSTREAM_END;}
static inline void qtx_set_reset(qstream_t *s) {s->flags |= QSTREAM_RESET;}

static inline bool qtx_can_send(qstream_t *s) {
	return s->tx.head < s->tx.tail || (s->flags & (QSTREAM_END | QSTREAM_RESET));
}

size_t qrx_read(qstream_t *s, void *data, size_t len);
void qtx_write(qstream_t *s, const void *data, size_t len);


