#include "qpack.h"
#include <cutils/endian.h>
#include <stdint.h>


static int64_t read_integer(qslice_t *s, uint8_t mask) {
	uint64_t ret = (*s->p++) & mask;
	if (ret != mask) {
		return ret;
	}
	ret = 0;
	while (s->p < s->e && !(ret >> 55)) {
		uint8_t val = *(s->p++);
		ret <<= 7;
		ret |= val & 0x7F;
		if (!(val & 0x80)) {
			return ret + mask;
		}
	}
	return -1;
}

static int write_integer(qslice_t *s, uint8_t flags, uint8_t mask, uint64_t value) {
	if (s->p == s->e) {
		return -1;
	} else if (value < mask) {
		*(s->p++) = flags | (uint8_t)value;
		return 0;
	} else {
		*(s->p++) = flags | mask;
		value -= mask;
		if (value > 0x7F) {
			size_t sz = (63 - clzl(value)) / 7;
			if (s->p + sz > s->e) {
				return -1;
			}
			do {
				*(s->p++) = 0x80 | (uint8_t)(value >> (sz * 7));
			} while (--sz);
		}
		if (s->p == s->e) {
			return -1;
		}
		*(s->p++) = (uint8_t)value & 0x7F;
		return 0;
	}
}

static int read_literal(qslice_t *s, uint8_t mask, qslice_t *buf, const uint8_t **pdata, uint16_t *plen) {
	uint8_t is_huffman = *s->p & (mask ^ (mask >> 1));
	int64_t len = read_integer(s, mask >> 1);
	if (len < 0 || len > (int64_t)(s->e - s->p) || len > UINT16_MAX) {
		return -1;
	}
	if (is_huffman) {
		*pdata = s->p;
		s->p += (size_t)len;
		*plen = (uint16_t)len;
		return 0;
	} else {
		*pdata = buf->p;
		ssize_t sz = hq_huffman_encode(buf, (char*)s->p, (size_t)len);
		if (sz < 0 || sz > UINT16_MAX) {
			return -1;
		}
		*plen = (uint16_t)sz;
		s->p += (size_t)len;
		return 0;
	}
}

static int write_literal(qslice_t *s, uint8_t hdr, uint8_t mask, const void *data, size_t len, int flags) {
	uint8_t huffman = (flags & HQ_PLAINTEXT) ? 0 : (mask ^ (mask >> 1));
	if (write_integer(s, hdr | huffman, mask >> 1, len)) {
		return -1;
	}
	if (s->p + len > s->e) {
		return -1;
	}
	s->p = append_mem(s->p, data, len);
	return 0;
}

static const hq_dict_entry_t *lookup_entry(qslice_t *s, uint8_t mask, const hq_dictionary_t *dict, bool negate, int *pindex) {
	if (!dict) {
		return NULL;
	}
	int64_t idx = read_integer(s, mask);
	if (idx < 0) {
		return NULL;
	}
	if (dict == &HQ_STATIC_DICT) {
		*pindex = (int)idx;
	} else {
		idx = dict->base + (negate ? -idx : idx);
	}
	if (idx < 0 || idx > dict->max) {
		return NULL;
	}
	return &dict->entries[idx % dict->num_entries];
}

#define INDEX_BOTH 0x80
#define INDEX_BOTH_STATIC 0x40
#define INDEX_BOTH_INDEX 0x3F

#define LITERAL_VALUE 0x40
#define LITERAL_VALUE_NEVER 0x20
#define LITERAL_VALUE_STATIC 0x10
#define LITERAL_VALUE_INDEX 0x0F
#define LITERAL_VALUE_LENGTH 0xFF

#define LITERAL_BOTH 0x20
#define LITERAL_BOTH_NEVER 0x10
#define LITERAL_BOTH_NAME 0x0F
#define LITERAL_BOTH_VALUE 0xFF

#define INDEX_POST 0x10
#define INDEX_POST_INDEX 0x0F

#define LITERAL_POST_NEVER 0x08
#define LITERAL_POST_INDEX 0x07
#define LITERAL_POST_VALUE 0xFF

#define HUFFMAN_ENCODED 0x80

int hq_decode_header(qslice_t *s, qslice_t *buf, const hq_dictionary_t *dict, hq_header *h) {
	assert(s->p < s->e);
	uint8_t hdr = *(s->p);
	h->static_index = -1;
	if (hdr & INDEX_BOTH) {
		if (hdr & INDEX_BOTH_STATIC) {
			dict = &HQ_STATIC_DICT;
		}
		const hq_dict_entry_t *e = lookup_entry(s, INDEX_BOTH_INDEX, dict, true, &h->static_index);
		if (!e) {
			return -1;
		}
		h->secure = false;
		h->key = dict->data + e->name_off;
		h->key_len = e->name_len;
		h->value = dict->data + e->value_off;
		h->value_len = e->value_len;
		return 0;

	} else if (hdr & LITERAL_VALUE) {
		if (hdr & LITERAL_VALUE_STATIC) {
			dict = &HQ_STATIC_DICT;
		}
		const hq_dict_entry_t *e = lookup_entry(s, LITERAL_VALUE_INDEX, dict, true, &h->static_index);
		if (!e || read_literal(s, LITERAL_VALUE_LENGTH, buf, &h->value, &h->value_len)) {
			return -1;
		}
		h->secure = (hdr & LITERAL_BOTH_NEVER) != 0;
		h->key = dict->data + e->name_off;
		h->key_len = e->name_len;
		return 0;

	} else if (hdr & LITERAL_BOTH) {
		h->secure = (hdr & LITERAL_BOTH_NEVER) != 0;
		return read_literal(s, LITERAL_BOTH_NAME, buf, &h->key, &h->key_len)
			|| read_literal(s, LITERAL_BOTH_VALUE, buf, &h->value, &h->value_len);

	} else if (hdr & INDEX_POST) {
		const hq_dict_entry_t *e = lookup_entry(s, INDEX_POST_INDEX, dict, false, NULL);
		if (!e) {
			return -1;
		}
		h->secure = false;
		h->key = dict->data + e->name_off;
		h->key_len = e->name_len;
		h->value = dict->data + e->value_off;
		h->value_len = e->value_len;
		return 0;

	} else {
		const hq_dict_entry_t *e = lookup_entry(s, LITERAL_POST_INDEX, dict, false, NULL);
		if (!e || read_literal(s, LITERAL_POST_VALUE, buf, &h->value, &h->value_len)) {
			return -1;
		}
		h->secure = false;
		h->key = dict->data + e->name_off;
		h->key_len = e->name_len;
		return 0;
	}
}

int hq_encode_header(qslice_t *s, const hq_header *hdr, const void *value, size_t len, int flags) {
	if (hdr->static_index >= 0) {
		if (!value) {
			return write_integer(s, INDEX_BOTH | INDEX_BOTH_STATIC, INDEX_BOTH_INDEX, (uint64_t)hdr->static_index);
		} else {
			uint8_t never = (flags & HQ_SECURE) ? LITERAL_VALUE_NEVER : 0;
			return write_integer(s, LITERAL_VALUE | LITERAL_VALUE_STATIC | never, LITERAL_VALUE_INDEX, (uint64_t)hdr->static_index)
				|| write_literal(s, 0, LITERAL_VALUE_LENGTH, value, len, flags);
		}
	} else {
		uint8_t never = (flags & HQ_SECURE) ? LITERAL_VALUE_NEVER : 0;
		return write_literal(s, LITERAL_BOTH | never, LITERAL_BOTH_NAME, hdr->key, hdr->key_len, 0)
			|| write_literal(s, 0, LITERAL_BOTH_VALUE, hdr->value, hdr->value_len, flags);
	}
}

