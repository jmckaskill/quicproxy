#pragma once
#include "common.h"
#include "buffer.h"
#include <cutils/rbtree.h>


struct qstream {
	rbnode rxnode;
	rbnode txnode;
	uint64_t id;

	qbuffer_t rx;
	qbuffer_t tx;

	uint64_t rx_end;
	uint64_t rx_data;
	uint64_t rx_max;
	uint64_t tx_sent;
	uint64_t tx_max;

	int rx_errnum;
	int rst_errnum;
	int stop_errnum;

	rbtree tx_packets;
	uint32_t flags;
};

void qinit_stream(qstream_t *s, void *txbuf, size_t txlen, void *rxbuf, size_t rxlen);

static inline uint64_t qrx_offset(qstream_t *s) {return s->rx.head;}
static inline uint64_t qrx_max(qstream_t *s) {return s->rx.tail;}
static inline size_t qrx_size(qstream_t *s) {return (size_t)(qrx_max(s) - qrx_offset(s));}
static inline bool qrx_eof(qstream_t *s) {return s->rx.head == s->rx_end;}
bool qrx_error(qstream_t *s);
void qrx_stop(qstream_t *s, int errnum);
size_t qrx_read(qstream_t *s, void *data, size_t len);

static inline uint64_t qtx_offset(qstream_t *s) {return s->tx.tail;}
static inline uint64_t qtx_max(qstream_t *s) {return qbuf_max(&s->tx);}
static inline size_t qtx_size(qstream_t *s) {return (size_t)(qtx_max(s) - qtx_offset(s));}
void qtx_finish(qstream_t *s);
void qtx_cancel(qstream_t *s, int errnum);
void qtx_write(qstream_t *s, const void *data, size_t len);



