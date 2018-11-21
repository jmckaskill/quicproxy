#include "buffer.h"

#define MIN(A,B) ((A) < (B) ? (A) : (B))

#if defined __GNUC__
static size_t ctz(uint32_t v) {
	return __builtin_ctz(v);
}
#elif defined _MSC_VER
#include <intrin.h>
#pragma intrinsic(_BitScanForward)
static size_t ctz(uint32_t v) {
	unsigned long ret;
	_BitScanForward(&ret, v);
	return ret;
}
#else
static size_t ctz(uint32_t v) {
	unsigned int c = 32;
	v &= -(int32_t)v;
	if (v) c--;
	if (v & 0x0000FFFF) c -= 16;
	if (v & 0x00FF00FF) c -= 8;
	if (v & 0x0F0F0F0F) c -= 4;
	if (v & 0x33333333) c -= 2;
	if (v & 0x55555555) c -= 1;
	return c;
}
#endif

void qbuf_init(qbuffer_t *b, bool tx, void *buf, size_t size) {
	// buffer is split into two circular buffers
	// Data bytes in chunks of 32B
	// Valid bits in chunks of 32b
	char *s = (char*)ALIGN_UP(uintptr_t, (uintptr_t)buf, 4);
	char *e = (char*)ALIGN_DOWN(uintptr_t, (uintptr_t)buf + size, 4);
	b->size = 32 * ((e - s) / (4 + 32));
	if (b->size) {
		b->valid = (uint32_t*)s;
		b->data = (char*)(s + (b->size / 4));
		memset(b->valid, tx ? 0xFF : 0, b->size / 4);
		if (tx) {
			b->tail = UINT32_MAX;
			b->valid[0] &= (UINT32_C(1) << 31) - 1;
		}
	} else {
		b->valid = NULL;
		b->data = NULL;
	}
	b->tail = 0;
	b->head = 0;
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

		// update the aligned middle - this may wrap around the circular buffer
		if (cstart > cend) {
			for (size_t c = cstart; c < (b->size >> 5); c++) {
				b->valid[c] = value;
			}
			for (size_t c = 0; c < cend; c++) {
				b->valid[c] = value;
			}
		} else {
			for (size_t c = cstart; c < cend; c++) {
				b->valid[c] = value;
			}
		}

		// update the bits leading out
		b->valid[cend] = set_bits_one_chunk(b->valid[cend], value, MASK(end & 31));
	}
}


size_t qbuf_insert(qbuffer_t *b, uint64_t off, size_t len, const void *data) {
	size_t start = (size_t)(off % b->size);
	size_t end = (start + len) % b->size;

	if (data) {
		if (end < start) {
			memcpy(b->data + start, data, b->size - start);
			memcpy(b->data, (char*)data + len - end, end);
		} else {
			memcpy(b->data + start, data, len);
		}
	}

	if (off != b->tail) {
		set_bits(b, ~UINT32_C(0), start, end);
		return 0;
	} else {
		// the new chunk is directly on the tail
		// move the buffer forward for the new data
		// and then work through the valid_buf to move
		// forward for later data that arrived earlier
		size_t ret = len;

		// look through the bits leading in
		if (end & 31) {
			uint32_t head_valid = b->valid[end / 32] >> (end & 31);
			size_t count = ctz(~head_valid);
			ret += count;
			if ((end + count) & 31) {
				goto end;
			}
		}

		// look through the valid chunks until the end of the circular buffer
		size_t c = (end + 31) >> 5;
		size_t csz = b->size >> 5;
		while (c < csz && b->valid[c] == ~UINT32_C(0)) {
			c++;
			ret += 32;
		}

		if (c == csz) {
			// look through the valid chunks at the start of the circular buffer
			c = 0;
			while (b->valid[c] == ~UINT32_C(0)) {
				c++;
				ret += 32;
			}
		}

		// look through the bits leading out
		uint32_t tail_valid = b->valid[c];
		ret += ctz(~tail_valid);

	end:
		b->tail += ret;
		return ret;
	}
}

size_t qbuf_buffer(qbuffer_t *b, void **pdata) {
	size_t start = (size_t)(b->head % b->size);
	size_t end = (size_t)(b->tail % b->size);
	*pdata = b->data + start;
	return (end < start) ? (b->size - start) : (end - start);
}

void qbuf_copy(qbuffer_t *b, uint64_t off, void *buf, size_t sz) {
	size_t start = (size_t)(off % b->size);
	size_t end = (start + sz) % b->size;

	if (start <= end) {
		size_t tocopy = MIN(sz, end - start);
		memcpy(buf, b->data + start, tocopy);
	} else if (start + sz < b->size) {
		memcpy(buf, b->data + start, sz);
	} else {
		size_t sz1 = b->size - start;
		memcpy(buf, b->data + start, sz1);
		sz -= sz1;
		buf = (char*)buf + sz1;
		size_t sz2 = MIN(sz, end);
		memcpy(buf, b->data, sz2);
	}
}

void qbuf_consume(qbuffer_t *b, size_t sz) {
	size_t start = (size_t)(b->head % b->size);
	size_t end = (start + sz) % b->size;
	set_bits(b, 0, start, end);
	b->head += sz;
}
