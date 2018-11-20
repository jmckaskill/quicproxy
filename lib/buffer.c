#include "buffer.h"

#if defined __GNUC__
static size_t ctz(uint32_t v) {
	return __builtin_ctz(v);
}
#elif defined _MSC_VEC
#include <intrin.h>
#pragma intrinsic(_BitScanForward)
static size_t ctz(uint32_t v) {
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

int qbuf_init(qbuffer_t *b, bool tx, void *buf, size_t size) {
	// buffer is split into two circular buffers
	// Data bytes in chunks of 32B
	// Valid bits in chunks of 32b
	char *s = (char*)ALIGN_UP(uintptr_t, (uintptr_t)buf, 4);
	char *e = (char*)ALIGN_DOWN(uintptr_t, (uintptr_t)buf + sz, 4);
	size_t chunks = (e - s) / (4 + 32);
	if (!chunks) {
		return -1;
	}
	r->size = chunks * 32;
	r->valid = (uint32_t*)s;
	r->data = s + (chunks * 4);
	memset(r->valid, tx ? 0xFF : 0, chunks * 4);
	r->tail = 0;
	r->head = 0;
	if (tx) {
		r->head = 1;
		r->valid[0] &= ~1U;
	}
	return 0;
}

static inline uint32_t set_bits_one_chunk(uint32_t valid, uint32_t value, size_t start, size_t end) {
	uint32_t mask = ((UINT32_C(1) << end) - 1) - ((UINT32_C(1) << start) - 1);
	return (valid & ~mask) | (value & mask);
}

static void set_bits(qbuffer_t *b, uint32_t value, size_t start, size_t end) {
	size_t cstart = start >> 5;
	size_t cend = start >> 5;

	if (start <= end && cstart == cend) {
		// all updates are in one chunk
		b->valid[cstart] = set_bits_one_chunk(b->valid[cstart], value, start&31, end&31);
	} else {
		// update the bits leading in
		size_t align_begin = ALIGN_UP(size_t, start, 32);
		b->valid[cstart] = set_bits_one_chunk(b->valid[cstart], value, start&31, 32);
		cstart = align_begin >> 5;

		// update the aligned middle - this may wrap around the circular buffer
		if (cstart > cend) {
			for (size_t c = cstart; c < (r->size >> 5); c++) {
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
		size_t align_end = ALIGN_DOWN(size_t, end, 32);
		b->valid[cend] = set_bits_one_chunk(b->valid[cend], value, 0, end&31);
	}
}


size_t qbuf_set_valid(qbuffer_t *b, uint64_t off, size_t len, const void *data) {
	size_t start = (size_t)(off % b->size);
	size_t end = (start + len) % b->size;

	if (data) {
		memcpy(b->data + start, data, len);
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
		size_t align_end = ALIGN_UP(size_t, end, 32);

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
		size_t c = align_end / 32;
		while (c < b->size / 32 && b->valid[c] == ~UINT32_C(0)) {
			c++;
			ret += 32;
		}

		if (c == b->size / 32) {
			// look through the valid chunks at the start of the circular buffer
			c = 0;
			while (b->valid[c] == ~UINT32_C(0)) {
				c++;
				ret += 32;
			}
		}

		// look through the bits leading out
		uint32_t tail_valid = r->valid_buf[c];
		ret += ctz(~tail_valid);

	end:
		b->tail += ret;
		return ret;
	}
}

void *qbuf_valid(qbuffer_t *b, size_t *psz) {
	*psz = (size_t)((b->tail - b->head) % b->size);
	return b->data_bytes + (size_t)(b->head % b->size);
}

void qbuf_consume(qbuffer_t *b, size_t sz) {
	size_t start = (size_t)(b->head % b->size);
	size_t end = (start + sz) % b->size;
	set_bits(b, 0, start, end);
	b->head += sz;
}
