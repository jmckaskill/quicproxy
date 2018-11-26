#pragma once
#include "common.h"
#include "buffer.h"
#include <cutils/rbtree.h>

#define QTX_COMPLETE 0x0001
#define QRX_COMPLETE 0x2000

#define QTX_QUEUED   0x0080
#define QTX_PENDING  0x8000

#define QTX_FIN      0x0002
#define QRX_FIN_ACK  0x0004
#define QRX_FIN      0x0200
#define QTX_RST      0x0008
#define QTX_RST_SENT 0x10000
#define QRX_RST_ACK  0x0010
#define QRX_RST      0x0400
#define QTX_STOP     0x0020
#define QTX_STOP_SENT 0x20000
#define QRX_STOP_ACK 0x0040
#define QRX_STOP     0x0800
#define QRX_DATA_ACK 0x4000
#define QTX_DIRTY    0x0100



#define STREAM_MAX UINT64_C(0x4000000000000000)

typedef struct qstream qstream_t;
struct qstream {
	rbnode rxnode;
	rbnode txnode;
	uint64_t id;

	qbuffer_t rx;
	qbuffer_t tx;

	uint64_t rx_end;
	uint64_t rx_data;
	uint64_t tx_next;
	uint64_t tx_max;

	int rx_errnum;
	int tx_errnum;

	rbtree tx_packets;
	uint32_t flags;
};

void qinit_stream(qstream_t *s, void *txbuf, size_t txlen, void *rxbuf, size_t rxlen);

static inline uint64_t qrx_offset(qstream_t *s) {return s->rx.head;}
static inline uint64_t qrx_max(qstream_t *s) {return s->rx.tail;}
static inline size_t qrx_size(qstream_t *s) {return (size_t)(qrx_max(s) - qrx_offset(s));}
static inline bool qrx_eof(qstream_t *s) {return s->rx.head == s->rx_end;}
static inline bool qrx_error(qstream_t *s) {return (s->flags | QRX_RESET) != 0;}
void qrx_stop(qstream_t *s);
size_t qrx_read(qstream_t *s, void *data, size_t len);

static inline uint64_t qtx_offset(qstream_t *s) {return s->tx.tail;}
static inline uint64_t qtx_max(qstream_t *s) {return qbuf_max(&s->tx);}
static inline size_t qtx_size(qstream_t *s) {return (size_t)(qtx_max(s) - qtx_offset(s));}
void qtx_finish(qstream_t *s);
void qtx_cancel(qstream_t *s, int errnum);
void qtx_write(qstream_t *s, const void *data, size_t len);

// These are used by the quic transport library
// append data, the stream may continue to use the provided buffer until the next call to fold
ssize_t qrx_received(qstream_t *s, bool fin, uint64_t offset, void *p, size_t sz);
static inline void qrx_fold(qstream_t *s) {qbuf_fold(&s->rx);}
void qtx_ack(qstream_t *s, uint64_t offset, size_t sz, uint64_t next);
void qtx_lost(qstream_t *s, uint64_t offset, size_t sz);
static inline bool qtx_eof(qstream_t *s, uint64_t off) {
	return off == s->tx.tail && (s->flags & QTX_FIN);
}


