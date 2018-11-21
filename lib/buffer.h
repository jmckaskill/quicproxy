#pragma once
#include "common.h"

// Circular buffer comprised of a valid range followed by a series of holes
// and valid parts. The head is moved back shrinking the size of the first valid
// range. The tail is moved back potentially subsuming valid ranges as holes
// are filled in.
// T moves as follows (+ indicates currently valid, x indicates set valid before next)
// |+++++|x |++| |++|
// H     T
// |++++++|x|++| |++|
// H      T
// |+++++++++++| |++|
// H           T
// For TX: valid indicates the byte can be written to. The first valid range
// is the append range. Head is the append point. Tail is the oldest byte not acknowledged.
// Thus head > tail.
// For RX: valid indicates the byte can be read. The first valid range is the
// completed but not consumed range. Head is the oldest byte not consumed. Tail is the
// most recent byte available for consumption.
// Head and tail are stored as u64, but the buffer always considers them % the buffer size.
// Data is stored in chunks of 32B which associates with a single uint32_t bitfield.
// The bitfield stores the valid bit LSB (ie 0x1 indicates the 0th byte is valid).

typedef struct qbuffer qbuffer_t;
struct qbuffer {
	uint64_t head;
	uint64_t tail;
	char *data;
	uint32_t *valid;
	size_t size; // circular buffer size in bytes
};

void qbuf_init(qbuffer_t *b, bool tx, void *buf, size_t size);

// set data valid after the tail. data may be NULL, in which case we'll just set the validity bits.
// returns the number of bytes now visible. May be 0 if the data is out of order.
size_t qbuf_insert(qbuffer_t *b, uint64_t off, size_t len, const void *data);

// First valid region chunk. Can be used for writing for tx or reading for rx.
// May not the full first valid region due to the circular buffer wrapping
// Call again after consuming data.
size_t qbuf_buffer(qbuffer_t *b, void **pdata);

void qbuf_copy(qbuffer_t *b, uint64_t off, void *buf, size_t sz);

// Consume data from the head of the valid region.
void qbuf_consume(qbuffer_t *b, size_t sz);

