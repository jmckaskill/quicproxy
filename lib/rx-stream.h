#pragma once
#include <cutils/rbtree.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef _MSC_VER
typedef ptrdiff_t ssize_t;
#endif

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

#define QRX_EOF -1
#define QRX_WAIT 0
// +ve = number of bytes in the buffer
ssize_t qrx_recv(qrx_stream_t *r, size_t min, void **pdata);

void qrx_consume(qrx_stream_t *r, size_t sz);

// These are used by the quic transport library
// append data, the stream may continue to use the provided buffer until the next call to fold
// can return QRX_EOF, QRX_WAIT or QRX_HAVE_DATA
#define QRX_HAVE_DATA 1
int qrx_append(qrx_stream_t *r, bool fin, uint64_t offset, void *p, size_t sz);
// fold the appended buffer into the local buffer
void qrx_fold(qrx_stream_t *r);



