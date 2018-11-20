#pragma once
#include "common.h"
#include <cutils/rbtree.h>

typedef struct qrx_stream qrx_stream_t;
struct qrx_stream {
	// opaque structure
	rbnode rb;			// sorting node for the QUIC main structure to lookup streams
	int64_t id;			// id of the stream (or -1 for unassigned/CRYPTO streams)
	uint64_t finish;	// full stream size - unknown until we see a fin

	uint64_t consumed;	// offset into the stream we've consumed
	uint64_t offset;	// offset into the stream that we have all data for

	char *data_buf;		// circular buffer of bytes containing data
	uint32_t *valid_buf;// circular buffer of bits indicating whether the data byte is valid
	size_t bufsz;		// size of circular buffer in bytes

	char *tail_ptr;		// tail data that hasn't been folded into the circular buffer yet
	size_t tail_size;
};

int qrx_init(qrx_stream_t *r, void *buf, size_t sz);

static inline bool qrx_have_finish(qrx_stream_t *r) {
	return r->offset == r->finish;
}

void *qrx_recv_buffer(qrx_stream_t *r, size_t min, size_t *psz);
void qrx_recv(qrx_stream_t *r, size_t sz);

// These are used by the quic transport library
// append data, the stream may continue to use the provided buffer until the next call to fold
// can return QRX_EOF, QRX_WAIT or QRX_HAVE_DATA
#define QRX_ERROR -1
#define QRX_WAIT 0
#define QRX_HAVE_DATA 1
int qrx_append(qrx_stream_t *r, bool fin, uint64_t offset, void *p, size_t sz);
// fold the appended buffer into the local buffer
void qrx_fold(qrx_stream_t *r);



