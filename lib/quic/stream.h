#pragma once
#include "common.h"
#include "buffer.h"
#include "source.h"
#include <cutils/rbtree.h>
#include <cutils/heap.h>

#define QSTREAM_MAX_TX_RANGES 16
#define QPENDING -1

struct qstream_list {
	struct qstream_list *next, *prev;
};

struct qstream_tx_range {
	uint64_t end, start;
};

struct qstream {
	rbnode rxnode;
	struct qstream_list data, ctrl;
	rbtree packets;
	const qsource_class **source;

	uint64_t id;
	qbuffer_t rx;

	uint64_t rx_max_received;
	uint64_t rx_max_allowed;
	uint64_t tx_max_sent;
	uint64_t tx_min_ack;

	int rx_errnum;
	int rst_errnum;
	int stop_errnum;

	uint32_t flags;
	qcontinuation cont;

	size_t to_send_num;
	struct qstream_tx_range to_send[QSTREAM_MAX_TX_RANGES];
};

void qinit_stream(qstream_t *s, void *rxbuf, size_t rxlen);

bool qrx_eof(qstream_t *s);
bool qrx_error(qstream_t *s);
void qrx_stop(qstream_t *s, int errnum);
size_t qrx_read(qstream_t *s, void *data, size_t len);

void qtx_cancel(qstream_t *s, int errnum);
size_t qtx_write(qstream_t *s, const void *data, size_t len);



