#include "rx-stream.h"
#include "packets.h"

static inline void clear_data(qrx_stream_t *r, size_t start, size_t end) {
#ifdef NDEBUG
	(void)r;
	(void)start;
	(void)end;
#else
	if (start <= end) {
		memset(r->data_buf + start, 0xDD, end - start);
	} else {
		memset(r->data_buf + start, 0xDD, r->bufsz - start);
		memset(r->data_buf, 0xDD, end);
	}
#endif
}

int qrx_init(qrx_stream_t *r, void *buf, size_t sz) {
	// buffer is split into two circular buffers
	// Data bytes in chunks of 32B
	// Valid bits in chunks of 32b
	char *s = (char*)ALIGN_UP(uintptr_t, (uintptr_t)buf, 4);
	char *e = (char*)ALIGN_DOWN(uintptr_t, (uintptr_t)buf + sz, 4);

	size_t chunks = (e - s) / (4 + 32);
	r->bufsz = chunks * 32;
	r->valid_buf = (uint32_t*)s;
	r->data_buf = s + (chunks * 4);
	memset(r->valid_buf, 0, chunks * 4);
	clear_data(r, 0, r->bufsz);

	r->id = -1;
	r->finish = UINT64_MAX;
	r->consumed = 0;
	r->offset = 0;
	r->tail_ptr = NULL;
	r->tail_size = 0;

	return chunks ? 0 : -1;
}

static void copy_tail(qrx_stream_t *r, char *p, size_t sz) {
	// copy the data
	size_t start = (size_t)(r->offset % r->bufsz);
	memcpy(r->data_buf + start, p, sz);

	// the new chunk is directly on the tail
	// move the buffer forward for the new data
	// and then work through the valid_buf to move
	// forward for later data that arrived earlier

	r->offset += sz;
	size_t end = (start + sz) % r->bufsz;
	size_t align_end = ALIGN_UP(size_t, end, 32);

	// look through the bits leading in
	if (end & 31) {
		uint32_t head_valid = r->valid_buf[end / 32];
		for (size_t b = end & 31; b < 32; b++) {
			if (!(head_valid & (1 << b))) {
				return;
			}
			r->offset++;
		}
	}

	// look through the valid chunks until the end of the circular buffer
	size_t c = align_end / 32;
	while (c < r->bufsz / 32 && r->valid_buf[c] == ~UINT32_C(0)) {
		c++;
		r->offset += 32;
	}

	if (c == r->bufsz / 32) {
		// look through the valid chunks at the start of the circular buffer
		while (c < start / 32 && r->valid_buf[c] == ~UINT32_C(0)) {
			c++;
			r->offset += 32;
		}
	}

	// look through the bits leading out
	size_t b = c * 32;
	uint32_t tail_valid = r->valid_buf[c];
	while (b < start && b < 32 && (tail_valid & (1 << b))) {
		r->offset++;
		b++;
	}
}

static inline uint32_t set_bits_one_chunk(uint32_t valid, uint32_t value, size_t start, size_t end) {
	size_t mask = ((1 << end) - 1) - ((1 << start) - 1);
	return (valid & ~mask) | (value & mask);
}

static void set_bits(qrx_stream_t *r, uint32_t value, size_t start, size_t end) {
	size_t cstart = start >> 5;
	size_t cend = start >> 5;

	if (start <= end && cstart == cend) {
		// all updates are in one chunk
		r->valid_buf[cstart] = set_bits_one_chunk(r->valid_buf[cstart], value, start, end);
	} else {
		// update the bits leading in
		size_t align_begin = ALIGN_UP(size_t, start, 32);
		r->valid_buf[cstart] = set_bits_one_chunk(r->valid_buf[cstart], value, start, align_begin);
		cstart = align_begin >> 5;

		// update the aligned middle - this may wrap around the circular buffer
		if (cstart > cend) {
			for (size_t c = cstart; c < (r->bufsz >> 32); c++) {
				r->valid_buf[c] = value;
			}
			for (size_t c = 0; c < cend; c++) {
				r->valid_buf[c] = value;
			}
		} else {
			for (size_t c = cstart; c < cend; c++) {
				r->valid_buf[c] = value;
			}
		}

		// update the bits leading out
		size_t align_end = ALIGN_DOWN(size_t, end, 32);
		r->valid_buf[cend] = set_bits_one_chunk(r->valid_buf[cend], value, align_end, end);
	}
}

static void copy_forward(qrx_stream_t *r, uint64_t offset, char *p, size_t sz) {
	// copy the data
	size_t start = (size_t)(offset % r->bufsz);
	size_t end = (start + sz) % r->bufsz;

	memcpy(r->data_buf + start, p, sz);

	// the new chunk is not directly on the tail
	// use the valid_buf to mark what bytes we've received
	// so that we can move the buffer forward the correct
	// amount when the hole is filled
	set_bits(r, ~UINT32_C(0), start, end);
}

int qrx_append(qrx_stream_t *r, bool fin, uint64_t offset, void *voidp, size_t sz) {
	char *p = voidp;

	uint64_t end = offset + sz;
	if (end <= r->offset) {
		// old data
		return 0;
	} else if (end > r->consumed + r->bufsz) {
		// flow control error
		return -1;
	} else if (end > r->finish) {
		// data past the end
		return -1;
	}
	
	if (fin) {
		if (r->finish == UINT64_MAX) {
			r->finish = end;
		} else if (r->finish != end) {
			// the stream end has shifted
			return -1;
		}
	}

	if (offset < r->offset) {
		// old start, but runs into new territory
		size_t shift = (size_t)(r->offset - offset);
		p += shift;
		sz -= shift;
		offset = r->offset;
	}

	if (offset == r->offset) {
		r->tail_ptr = p;
		r->tail_size = sz;
	} else {
		copy_forward(r, offset, p, sz);
	}

	return 0;
}

void qrx_fold(qrx_stream_t *r) {
	if (r->tail_size) {
		copy_tail(r, r->tail_ptr, r->tail_size);
		r->tail_ptr = NULL;
		r->tail_size = 0;
	}
}

ssize_t qrx_recv(qrx_stream_t *r, size_t min, void **pdata) {
	if (r->consumed + min > r->finish) {
		return QRX_EOF;
	}

	if (r->offset == r->consumed && min <= r->tail_size) {
		// use data direct from the tail
		*pdata = r->tail_ptr;
		return r->tail_size;
	} else {
		// use data from the buffer
		uint64_t need = r->consumed + min;
		if (need > r->offset) {
			// need to fold in some of the tail to service this request

			if (!r->tail_size) {
				// no tail available
				return QRX_WAIT;
			}

			size_t tocopy = need - r->offset;
			if (tocopy > r->tail_size) {
				tocopy = r->tail_size;
			}
			copy_tail(r, r->tail_ptr, tocopy);
			r->tail_ptr += tocopy;
			r->tail_size -= tocopy;

			if (need > r->offset) {
				// even after copying in the tail and using out of order data
				// we still don't have enough
				return QRX_WAIT;
			}
		}

		size_t pos = (size_t)(r->consumed % r->bufsz);
		*pdata = r->data_buf + pos;
		return (ssize_t)(r->offset - r->consumed);
	}
}

void qrx_consume(qrx_stream_t *r, size_t sz) {
	// need to unset bits in the valid buffer
	size_t start = (size_t)(r->consumed % r->bufsz);
	size_t end = (start + sz) % r->bufsz;
	set_bits(r, 0, start, end);
	clear_data(r, start, end);

	if (r->offset == r->consumed) {
		assert(sz <= r->tail_size);
		r->tail_ptr += sz;
		r->tail_size -= sz;
		r->offset += sz;
	}

	r->consumed += sz;
	assert(r->consumed <= r->offset + r->tail_size);
}

