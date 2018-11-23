#pragma once
#include "common.h"

// Circular buffer that comprises a series of blocks and gaps.
// Head points to the start of the first block. Tail points to the end of the last complete block.
// The head and tail can only be increased. They are moved by adding or removing data.
// Data can be added anywhere after the head including after the tail up to the point
// where the buffer becomes too large. 
//
// On addition:
// - Tail is moved forward if it is a contiguous movement of now valid bytes
// - Head is not touched
//
// On removal:
// - Head is moved forward if it is a contiguous movement of now removed bytes
// - Tail is not touched
//
// T moves as follows (+ indicates currently valid, x indicates set valid before next)
// |+++++|x |++| |++|
// H     T
// |++++++|x|++| |++|
// H      T
// |+++++++++++| |++|
// H           T
// This buffer is used for both transmit and receive.
//
// When used for transmit:
// - Local data is appended (typically in order)
// - Data is removed as acks come back
// - Head indicates oldest byte not yet acknowledged
// - Tail indicates newest byte available to transmit
//
// When used for receive:
// - Received data is appended (might be in order)
// - Data is removed as data is consumed by the app
// - Head indicates oldest byte not yet consumed
// - Tail indicates newest byte available for consumption
//
// The buffer temporarily stores the originally buffer on an insert.
// For TX this allows a large static or mmaped buffer to be used
// For RX this allows the data within a packet to be consumed directly if immediately consumed
// qbuf_fold should be called to fold the data into the buffer proper. It must be called
// before the next call to qbuf_insert. However calls to qbuf_remove can occur in between, which
// may reduce the amount of data that actually gets copied.
//
// Data is stored in chunks of 32B which associates with a single uint32_t bitfield.
// The bitfield stores the valid bit LSB (ie 0x1 indicates the 0th byte is valid).

typedef struct qbuffer qbuffer_t;
struct qbuffer {
	uint64_t head;
	uint64_t tail;
	uint64_t ext_off;
	const char *ext_data;
	size_t ext_len;
	char *data;
	size_t size;
	uint32_t *valid;
};

void qbuf_init(qbuffer_t *b, void *buf, size_t size);

// returns the limits we can accept data within
static inline uint64_t qbuf_min(qbuffer_t *b) {return b->head;}
static inline uint64_t qbuf_max(qbuffer_t *b) {return b->head + b->size - 1;}

// returns how far the tail has moved
size_t qbuf_insert(qbuffer_t *b, uint64_t off, const void *data, size_t len);
void qbuf_fold(qbuffer_t *b);

void qbuf_mark_invalid(qbuffer_t *b, uint64_t off, size_t len);
void qbuf_mark_valid(qbuffer_t *b, uint64_t off, size_t len);
void qbuf_consume(qbuffer_t *b, uint64_t max);

size_t qbuf_data(qbuffer_t *b, uint64_t off, const void **pdata);
size_t qbuf_copy(qbuffer_t *b, uint64_t off, void *buf, size_t sz);
bool qbuf_next_valid(qbuffer_t *b, uint64_t *off);


