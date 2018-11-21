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

	char *tail_ptr;		// received data that hasn't been folded into the circular buffer yet
	size_t tail_size;

	uint8_t flags;
};

// For functions returning ssize_t
#define QRX_FLOW_CONTROL -2
#define QRX_WAIT -1
#define QRX_EOF 0

void qinit_stream(qstream_t *s, void *txbuf, size_t txlen, void *rxbuf, size_t rxlen);

void qrx_consume(qstream_t *s, size_t sz);
// returns number of bytes read or one of the QRX error codes
ssize_t qrx_buffer(qstream_t *s, void **pdata);
ssize_t qrx_read(qstream_t *s, void *buf, size_t sz);
size_t qrx_read_all(qstream_t *s, void *buf, size_t sz, bool *fin);
static inline uint64_t qrx_offset(qstream_t *s) {return s->rx.head;}

// These are used by the quic transport library
// append data, the stream may continue to use the provided buffer until the next call to fold
// returns -ve = flow control error, 0 = wait, +ve = have data
int qrx_received(qstream_t *s, bool fin, uint64_t offset, void *p, size_t sz);
// fold the appended buffer into the local buffer
void qrx_fold(qstream_t *r);

uint64_t qrx_max(qstream_t *s);
size_t qtx_in_flight(qstream_t *s);

size_t qtx_write(qstream_t *s, const void *buf, size_t sz);
static inline void qtx_finish(qstream_t *s) {s->flags |= QSTREAM_END;}
static inline void qtx_reset(qstream_t *s) {s->flags |= QSTREAM_RESET;}



