#include "buffer.h"

#define MIN(A,B) ((A) < (B) ? (A) : (B))

// ctz = count trailing zeros
// These versions do not protect against a zero value.
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
	unsigned n = 0;
	while (!(v & 1)) {
		n++;
		v >>= 1;
	}
	return n;
}
#endif

void qbuf_init(qbuffer_t *b, void *buf, size_t size) {
	// buffer is split into two circular buffers
	// Data bytes in chunks of 32B
	// Valid bits in chunks of 32b
	char *s = (char*)ALIGN_UP(uintptr_t, (uintptr_t)buf, 4);
	char *e = (char*)ALIGN_DOWN(uintptr_t, (uintptr_t)buf + size, 4);
	b->size = 32 * ((e - s) / (4 + 32));
	b->head = 0;
	b->tail = 0;
	b->ext_off = 0;
	b->ext_data = NULL;
	b->ext_len = 0;
	b->valid = (uint32_t*)s;
	b->data = (char*)s + (b->size / 8);
	memset(b->valid, 0, b->size / 8);
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

static size_t iterate_bits(qbuffer_t *b, uint32_t value, size_t start, size_t end) {
	// look through the bits leading in
	size_t ret = 0;
	size_t sbits = start & 31;
	size_t ebits = end & 31;
	size_t cend = end >> 5;
	size_t csz = b->size >> 5;
	size_t c = start >> 5;

	if (sbits) {
		// align the head, we want the top (32-n) bits on the right for the ctz
		// sbits != 0 and sbits != 32, thus some of ~value will end up in head_valid
		// Thus ctz is not called with a 0 value.
		uint32_t head_valid = (b->valid[c] >> sbits) | (~value << (32 - sbits));
		size_t count = ctz(head_valid ^ value);
		if (c == cend && start <= end) {
			return MIN(end - start, count);
		} else if ((start + count) & 31) {
			return count;
		}
		ret = count;
		c++;
	}

	// look through the valid chunks until the end of the circular buffer
	for (;;) {
		if (c == cend) {
			goto tail;
		} else if (c == csz) {
			goto from_start;
		} else if (b->valid[c] != value) {
			goto lead_out;
		}
		c++;
		ret += 32;
	}

	// look through the valid chunks at the start of the circular buffer
from_start:
	c = 0;
	for (;;) {
		if (c == cend) {
			goto tail;
		} else if (b->valid[c] != value) {
			goto lead_out;
		}
		c++;
		ret += 32;
	}

lead_out:
	// look through the bits leading out
	// the calling code guarantees b->valid[c] != value
	// hence ctz doesn't get called with a 0 value
	assert(b->valid[c] != value);
	return ret + ctz(b->valid[c] ^ value);

tail:
	// we've hit our iteration limit
	if (!ebits) {
		return ret;
	}
	// deal with the unaligned tail
	// we want the bottom n bits on the right
	uint32_t mask = ((uint32_t)1 << ebits) - 1;
	uint32_t tail_valid = (b->valid[c] & mask) | (~value << ebits);
	// ebits != 0 && ebits != 32, thus mask is not all zeros or ones
	// some of ~value will be in tail_valid, thus ctz will not be called
	// with a 0 value
	assert(tail_valid != value);
	return ret + ctz(tail_valid ^ value);
}

void qbuf_fold(qbuffer_t *b) {
	if (b->ext_len) {
		size_t start = (size_t)(b->ext_off % b->size);
		size_t end = (start + b->ext_len) % b->size;

		// The ideal is to iterate over the valid bitset and only
		// copy when the bit is 1. That's too complex and is rarely needed.
		// The most common use case is a received packet that was contiguously
		// consumed from the front. So restrict the start point, but don't
		// bother with the rear or holes in between.
		size_t shift = iterate_bits(b, 0, start, end);
		start = (start + shift) % b->size;

		if (end < start) {
			memcpy(b->data + start, b->ext_data + shift, b->size - start);
			memcpy(b->data, b->ext_data + b->ext_len - end, end);
		} else if (end > start) {
			memcpy(b->data + start, b->ext_data + shift, b->ext_len - shift);
		}

		b->ext_off = 0;
		b->ext_data = NULL;
		b->ext_len = 0;
	}
}

size_t qbuf_insert(qbuffer_t *b, uint64_t off, const void *data, size_t len) {
	if (off + len <= b->tail) {
		// old data
		return 0;
	}
	if (off < b->tail) {
		// old start, but going into new territory
		size_t shift = (size_t)(b->tail - off);
		off = b->tail;
		data = (char*)data + shift;
		len -= shift;
	}
	assert(qbuf_min(b) <= off && off + len <= qbuf_max(b));
	assert(!b->ext_data);
	b->ext_off = off;
	b->ext_data = (const char*)data;
	b->ext_len = len;

	size_t start = (size_t)(off % b->size);
	size_t end = (start + len) % b->size;
	set_bits(b, ~UINT32_C(0), start, end);

	if (off == b->tail) {
		len += iterate_bits(b, ~UINT32_C(0), end, (size_t)((b->head + b->size) % b->size));
		b->tail += len;
		return len;
	} else {
		return 0;
	}
}

size_t qbuf_consume(qbuffer_t *b, uint64_t max) {
	assert(max <= b->tail);
	size_t start = (size_t)(b->head % b->size);
	size_t end = (size_t)(max % b->size);
	size_t len = iterate_bits(b, 0, start, end);
	b->head += len;
	return len;
}

void qbuf_mark_invalid(qbuffer_t *b, uint64_t off, size_t len) {
	assert(b->head <= off && off + len <= b->tail);
	size_t start = (size_t)(off % b->size);
	size_t end = (start + len) % b->size;
	set_bits(b, 0, start, end);
}

void qbuf_mark_valid(qbuffer_t *b, uint64_t off, size_t len) {
	assert(b->head <= off && off + len <= b->tail);
	size_t start = (size_t)(off % b->size);
	size_t end = (start + len) % b->size;
	set_bits(b, ~UINT32_C(0), start, end);
}

static size_t get_internal_data(qbuffer_t *b, size_t start, size_t len, const void **pdata) {
	size_t end = (start + len) % b->size;
	if (start <= end) {
		*pdata = b->data + start;
		return len;
	} else {
		// internal buffer has wrapped around, take the rest up to the end
		*pdata = b->data + start;
		return b->size - start;
	}
}

size_t qbuf_data(qbuffer_t *b, uint64_t off, const void **pdata) {
	assert(qbuf_min(b) <= off && off <= qbuf_max(b));
	size_t start = (size_t)(off % b->size);
	size_t end = (size_t)(b->tail % b->size);
	size_t len = iterate_bits(b, ~UINT32_C(0), start, end);

	if (!len) {
		*pdata = NULL;
		return 0;

	} else if (off >= b->ext_off + b->ext_len) {
		// we start after the external buffer
		return get_internal_data(b, start, len, pdata);

	} else if (off >= b->ext_off) {
		// we start in the external buffer
		size_t into_ext = (size_t)(off - b->ext_off);
		*pdata = b->ext_data + into_ext;
		return MIN(len, b->ext_len - into_ext);

	} else {
		// we start before the external buffer
		return get_internal_data(b, start, MIN(len, (size_t)(b->ext_off - off)), pdata);
	}
}

size_t qbuf_copy(qbuffer_t *b, uint64_t off, void *buf, size_t sz) {
	assert(b->head <= off && off <= b->tail);
	size_t ret = 0;
	size_t have;
	const void *src;
	while (ret < sz && (have = qbuf_data(b, off + ret, &src)) != 0) {
		memcpy((char*)buf + ret, src, have);
		ret += have;
	}
	return ret;
}

bool qbuf_next_valid(qbuffer_t *b, uint64_t *off) {
	assert(b->head <= *off && *off <= b->tail);
	size_t start = (size_t)(*off % b->size);
	size_t end = (size_t)(b->tail % b->size);
	*off += iterate_bits(b, 0, start, end);
	return *off < b->tail;
}

bool qbuf_any_valid_after(qbuffer_t *b, uint64_t off) {
	if (off < b->tail) {
		return true;
	}
	size_t start = (size_t)(off % b->size);
	size_t end = (size_t)(qbuf_max(b) % b->size);
	size_t len = iterate_bits(b, 0, start, end);
	return start + len < end;
}
