#include "buffer.h"
#include "internal.h"


void qbuf_init(qbuffer_t *b, void *buf, size_t size) {
	// buffer is split into two circular buffers
	// Data bytes in chunks of 32B
	// Valid bits in chunks of 32b
	char *s = (char*)ALIGN_UP((uintptr_t)buf, (uintptr_t)4);
	char *e = (char*)ALIGN_DOWN((uintptr_t)buf + size, (uintptr_t)4);
	size_t chunks = (e - s) / (4 + 32);
	b->size = 32 * chunks;
	b->used = 0;
	b->have = 0;
	b->ext_data = NULL;
	b->valid = (uint32_t*)s;
	b->data = (char*)s + (b->size / 8);
	memset(b->valid, 0, b->size / 8);
#ifndef NDEBUG
	memset(b->data, 0xEE, b->size);
#endif
}

static void compact_buffer(qbuffer_t *b) {
	assert(!b->ext_data);
	size_t cstart = b->used >> 5;
	size_t bstart = cstart << 5;
	size_t total_chunks = b->size >> 5;
	size_t keep_chunks = total_chunks - cstart;
	size_t keep_bytes = keep_chunks << 5;
	memmove(b->valid, b->valid + cstart, keep_chunks * 4);
	memset(b->valid + keep_chunks, 0, (total_chunks - keep_chunks) * 4);
	memmove(b->data, b->data + bstart, keep_bytes);
#ifndef NDEBUG
	memset(b->data + keep_bytes, 0xEE, b->size - keep_bytes);
#endif
	b->used -= bstart;
	b->have -= bstart;
	b->off += bstart;
}

static inline uint32_t set_bits_one_chunk(uint32_t valid, uint32_t value, uint32_t mask) {
	return (valid & ~mask) | (value & mask);
}

// creates a mask of 1s on the right sz long
#define MASK(SZ) ((UINT32_C(1) << (SZ)) - 1)

static void set_bits(qbuffer_t *b, uint32_t value, size_t start, size_t end) {
	size_t cstart = start >> 5;
	size_t cend = end >> 5;

	if (start <= end && cstart == cend) {
		// all updates are in one chunk
		uint32_t mask = MASK(end & 31) - MASK(start & 31);
		b->valid[cstart] = set_bits_one_chunk(b->valid[cstart], value, mask);
	} else {
		// update the bits leading in
		b->valid[cstart] = set_bits_one_chunk(b->valid[cstart], value, ~MASK(start & 31));
		cstart = (start + 31) >> 5;

		// update the aligned middle
		for (size_t c = cstart; c < cend; c++) {
			b->valid[c] = value;
		}

		// update the bits leading out
		b->valid[cend] = set_bits_one_chunk(b->valid[cend], value, MASK(end & 31));
	}
}

static size_t iterate_bits(const qbuffer_t *b, uint32_t value, size_t start) {
	// look through the bits leading in
	size_t ret = 0;
	size_t sbits = start & 31;
	size_t csz = b->size >> 5;
	size_t c = start >> 5;

	if (sbits) {
		// align the head, we want the top (32-n) bits on the right for the ctz
		// sbits != 0 and sbits != 32, thus some of ~value will end up in head_valid
		// Thus ctz is not called with a 0 value.
		uint32_t head_valid = (b->valid[c] >> sbits) | (~value << (32 - sbits));
		size_t count = ctz(head_valid ^ value);
		if ((start + count) & 31) {
			return count;
		}
		ret = count;
		c++;
	}

	// look through the valid chunks until the end of the circular buffer
	while (c < csz) {
		if (b->valid[c] != value) {
			// look through the bits leading out
			return ret + ctz(b->valid[c] ^ value);
		}
		c++;
		ret += 32;
	}

	return ret;
}

void qbuf_fold(qbuffer_t *b) {
	if (b->ext_data && b->used < b->have) {
		memcpy(b->data + b->used, b->ext_data + b->used, b->have - b->used);
	}
	b->ext_data = NULL;
}

size_t qbuf_insert(qbuffer_t *b, uint64_t off, const void *data, size_t len) {
	uint64_t done = b->off + b->have;
	uint64_t end = off + len;
	if (end <= done) {
		// old data
		return 0;
	} else if (off < done) {
		// old start, but going into new territory
		size_t shift = (size_t)(done - off);
		off = done;
		data = (char*)data + shift;
		len -= shift;
	}

	assert(!b->ext_data);
	assert(end <= qbuf_max(b));

	if (end > b->off + b->size) {
		compact_buffer(b);
	}

	if (off == done) {
		// data is right on the tail
		size_t exposed = iterate_bits(b, ~UINT32_C(0), b->have + len);
		if (!exposed && b->have == b->used) {
			b->ext_data = data;
			b->have += len;
		} else {
			memcpy(b->data + b->have, data, len);
			b->have += len + exposed;
		}
		return len + exposed;
	} else {
		size_t boff = (size_t)(off - b->off);
		memcpy(b->data + boff, data, len);
		set_bits(b, ~UINT32_C(0), boff, boff + len);
		return 0;
	}
}

size_t qbuf_data(const qbuffer_t *b, uint64_t *poff, const void **pdata) {
	*poff = b->off + b->used;
	*pdata = (b->ext_data ? b->ext_data : b->data) + b->used;
	return b->have - b->used;
}

void qbuf_consume(qbuffer_t *b, size_t consume) {
#ifndef NDEBUG
	memset(b->data + b->used, 0xEE, consume);
#endif
	set_bits(b, 0, b->used, b->used + consume);
	b->used += consume;
}

