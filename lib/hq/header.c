#include "header.h"
#include <cutils/endian.h>

#define ARRAYSZ(A) (sizeof(A) / sizeof((A)[0]))
static_assert(HQ_MAX_HEADERS+1 < 256, "header index must fit in one byte");

static bool hdr_key_equals(const hq_header *a, const hq_header *b) {
	return a->key == b->key
		|| (a->key_len == b->key_len && a->hash == b->hash && !memcmp(a->key, b->key, a->key_len));
}

static uint8_t find_empty_index(hq_header_table *t) {
	for (uint8_t i = 0; i < ARRAYSZ(t->used); i++) {
		if (t->used[i] != ~UINT32_C(0)) {
			return (i * 32) + ctz(~t->used[i]) + 1;
		}
	}
	return 0;
}

static hq_header *get_header(hq_header_table *t, uint8_t idx) {
	assert(idx && idx < HQ_MAX_HEADERS);
	return &t->headers[idx - 1];
}

static hq_header *insert_header(hq_header_table *t, uint8_t idx) {
	int off = idx - 1;
	assert(idx && idx < HQ_MAX_HEADERS && !(t->used[off >> 5] & (1 << (off & 31))));
	t->used[off >> 5] |= 1 << (off & 31);
	return &t->headers[off];
}

static void remove_header(hq_header_table *t, uint8_t *pidx) {
	int off = *pidx - 1;
	assert(*pidx && *pidx < HQ_MAX_HEADERS && (t->used[off >> 5] & (1 << (off & 31))));
	t->used[off >> 5] &= ~(1 << (off & 31));
	*pidx = t->headers[off].next;
}

static bool find_header(hq_header_table *t, const hq_header *k, uint8_t **ppidx) {
	*ppidx = &t->table[k->hash];
	while (**ppidx) {
		hq_header *h = get_header(t, **ppidx);
		if (hdr_key_equals(h, k)) {
			return true;
		}
		*ppidx = &h->next;
	}
	return false;
}

uint8_t hq_compute_hash(const uint8_t *key, size_t len) {
	// FNV-1a using the 32b parameters
	uint32_t u = UINT32_C(0x811c9dc5);
	for (size_t i = 0; i < len; i++) {
		u ^= key[i];
		u *= 16777619;
	}
	return (uint8_t)(u % HQ_HEADER_TABLE_SIZE);
}

static int do_insert(hq_header_table *t, uint8_t *pidx, const hq_header *h, const void *value, size_t len, int flags) {
	if (len > HQ_MAX_HEADER_SIZE) {
		return -1;
	}

	uint8_t hidx = find_empty_index(t);
	if (!hidx) {
		return -1;
	}

	// create the new header entry
	hq_header *c = insert_header(t, hidx);
	*c = *h;
	if (value) {
		c->value = value;
		c->value_flags = (uint16_t)flags | ((uint16_t)len << HQ_HEADER_VALUE_LEN_SHIFT);
	}
	
	// and insert it into the chain
	c->next = *pidx;
	*pidx = hidx;
	return 0;
}

int hq_hdr_set(hq_header_table *t, const hq_header *h, const void *value, size_t len, int flags) {
	uint8_t *pidx;

	// remove the existing entries
	if (find_header(t, h, &pidx)) {
		do {
			remove_header(t, pidx);
		} while (*pidx && hdr_key_equals(get_header(t, *pidx), h));
	}

	return do_insert(t, pidx, h, value, len, flags);
}

int hq_hdr_add(hq_header_table *t, const hq_header *h, const void *value, size_t len, int flags) {
	uint8_t *pidx;

	// find the end of the existing chain
	if (find_header(t, h, &pidx)) {
		do {
			hq_header *n = get_header(t, *pidx);
			pidx = &n->next;
		} while (*pidx && hdr_key_equals(get_header(t, *pidx), h));
	}

	return do_insert(t, pidx, h, value, len, flags);
}

int hq_hdr_remove(hq_header_table *t, const hq_header *h) {
	uint8_t *pidx;
	if (!find_header(t, h, &pidx)) {
		return -1;
	}

	do {
		remove_header(t, pidx);
	} while (*pidx && hdr_key_equals(get_header(t, *pidx), h));

	return 0;
}

const hq_header *hq_hdr_get(hq_header_table *t, const hq_header *h) {
	uint8_t *pidx;
	return find_header(t, h, &pidx) ? get_header(t, *pidx) : NULL;
}

const hq_header *hq_hdr_next(hq_header_table *t, const hq_header *h) {
	if (!h->next) {
		return NULL;
	}
	const hq_header *n = get_header(t, h->next);
	return hdr_key_equals(n, h) ? n : NULL;
}

const uint32_t hq_hdr_encoder[] = {
	0x14 | (6 << 24),    // ' ' (32)  | 010100
	0x3F8 | (10 << 24),  // '!' (33)  | 11111110
	0x3f9 | (10 << 24),  // '"' (34)  | 1111111001
	0xffa | (12 << 24),  // '#' (35)  | 111111111010
	0x1ff9 | (13 << 24), // '$' (36)  | 1111111111001
	0x15 | (6 << 24),    // '%' (37)  | 010101
	0xf8 | (8 << 24),    // '&' (38)  | 11111000
	0x7fa | (11 << 24),  // ''' (39)  | 11111111010
	0x3fa | (10 << 24),  // '(' (40)  | 1111111010
	0x3fb | (10 << 24),  // ')' (41)  | 1111111011
	0xf9 | (8 << 24),    // '*' (42)  | 11111001
	0x7fb | (11 << 24),  // '+' (43)  | 11111111011
	0xfa | (8 << 24),    // ',' (44)  | 11111010
	0x16 | (6 << 24),    // '-' (45)  | 010110
	0x17 | (6 << 24),    // '.' (46)  | 010111
	0x18 | (6 << 24),    // '/' (47)  | 011000
	0x0 | (5 << 24),     // '0' (48)  | 00000
	0x1 | (5 << 24),     // '1' (49)  | 00001
	0x2 | (5 << 24),     // '2' (50)  | 00010
	0x19 | (6 << 24),    // '3' (51)  | 011001
	0x1a | (6 << 24),    // '4' (52)  | 011010
	0x1b | (6 << 24),    // '5' (53)  | 011011
	0x1c | (6 << 24),    // '6' (54)  | 011100
	0x1d | (6 << 24),    // '7' (55)  | 011101
	0x1e | (6 << 24),    // '8' (56)  | 011110
	0x1f | (6 << 24),    // '9' (57)  | 011111
	0x5c | (7 << 24),    // ':' (58)  | 1011100
	0xfb | (8 << 24),    // ';' (59)  | 11111011
	0x7ffc | (15 << 24), // '<' (60)  | 111111111111100
	0x20 | (6 << 24),    // '=' (61)  | 100000
	0xffb | (12 << 24),  // '>' (62)  | 111111111011
	0x3fc | (10 << 24),  // '?' (63)  | 1111111100
	0x1ffa | (13 << 24), // '@' (64)  | 1111111111010
	0x21 | (6 << 24),    // 'A' (65)  | 100001
	0x5d | (7 << 24),    // 'B' (66)  | 1011101
	0x5e | (7 << 24),    // 'C' (67)  | 1011110
	0x5f | (7 << 24),    // 'D' (68)  | 1011111
	0x60 | (7 << 24),    // 'E' (69)  | 1100000
	0x61 | (7 << 24),    // 'F' (70)  | 1100001
	0x62 | (7 << 24),    // 'G' (71)  | 1100010
	0x63 | (7 << 24),    // 'H' (72)  | 1100011
	0x64 | (7 << 24),    // 'I' (73)  | 1100100
	0x65 | (7 << 24),    // 'J' (74)  | 1100101
	0x66 | (7 << 24),    // 'K' (75)  | 1100110
	0x67 | (7 << 24),    // 'L' (76)  | 1100111
	0x68 | (7 << 24),    // 'M' (77)  | 1101000
	0x69 | (7 << 24),    // 'N' (78)  | 1101001
	0x6a | (7 << 24),    // 'O' (79)  | 1101010
	0x6b | (7 << 24),    // 'P' (80)  | 1101011
	0x6c | (7 << 24),    // 'Q' (81)  | 1101100
	0x6d | (7 << 24),    // 'R' (82)  | 1101101
	0x6e | (7 << 24),    // 'S' (83)  | 1101110
	0x6f | (7 << 24),    // 'T' (84)  | 1101111
	0x70 | (7 << 24),    // 'U' (85)  | 1110000
	0x71 | (7 << 24),    // 'V' (86)  | 1110001
	0x72 | (7 << 24),    // 'W' (87)  | 1110010
	0xfc | (8 << 24),    // 'X' (88)  | 11111100
	0x73 | (7 << 24),    // 'Y' (89)  | 1110011
	0xfd | (8 << 24),    // 'Z' (90)  | 11111101
	0x1ffb | (13 << 24), // '[' (91)  | 1111111111011
	0x7fff0 | (19 << 24),// '\' (92)  | 1111111111111110000
	0x1ffc | (13 << 24), // ']' (93)  | 1111111111100
	0x3ffc | (14 << 24), // '^' (94)  | 11111111111100
	0x22 | (6 << 24),    // '_' (95)  | 100010
	0x7ffd | (15 << 24), // '`' (96)  | 111111111111101
	0x3 | (5 << 24),     // 'a' (97)  | 00011
	0x23 | (6 << 24),    // 'b' (98)  | 100011
	0x4 | (5 << 24),     // 'c' (99)  | 00100
	0x24 | (6 << 24),    // 'd' (100) | 100100
	0x5 | (5 << 24),     // 'e' (101) | 00101
	0x25 | (6 << 24),    // 'f' (102) | 100101
	0x26 | (6 << 24),    // 'g' (103) | 100110
	0x27 | (6 << 24),    // 'h' (104) | 100111
	0x6 | (5 << 24),     // 'i' (105) | 00110
	0x74 | (7 << 24),    // 'j' (106) | 1110100
	0x75 | (7 << 24),    // 'k' (107) | 1110101
	0x28 | (6 << 24),    // 'l' (108) | 101000
	0x29 | (6 << 24),    // 'm' (109) | 101001
	0x2a | (6 << 24),    // 'n' (110) | 101010
	0x7 | (5 << 24),     // 'o' (111) | 00111
	0x2b | (6 << 24),    // 'p' (112) | 101011
	0x76 | (7 << 24),    // 'q' (113) | 1110110
	0x2c | (6 << 24),    // 'r' (114) | 101100
	0x8 | (5 << 24),     // 's' (115) | 01000
	0x9 | (5 << 24),     // 't' (116) | 01001
	0x2d | (6 << 24),    // 'u' (117) | 101101
	0x77 | (7 << 24),    // 'v' (118) | 1110111
	0x78 | (7 << 24),    // 'w' (119) | 1111000
	0x79 | (7 << 24),    // 'x' (120) | 1111001
	0x7a | (7 << 24),    // 'y' (121) | 1111010
	0x7b | (7 << 24),    // 'z' (122) | 1111011
	0x7ffe | (15 << 24), // '{' (123) | 111111111111110
	0x7fc | (11 << 24),  // '|' (124) | 11111111100
	0x3ffd | (14 << 24), // '}' (125) | 11111111111101
	0x1ffd | (13 << 24), // '~' (126) | 1111111111101
	0,
};

struct huffman_encoder {
	uint8_t *p, *e;
	uint32_t bits;
	uint32_t value;
};

static int encode_character(struct huffman_encoder *e, char ch) {
	uint32_t n = hq_hdr_encoder[ch - ' '];
	e->value <<= (n >> 24);
	e->value |= (n & 0xFFFFFF);
	e->bits += (n >> 24);
	for (;;) {
		if (e->bits < 8) {
			return 0;
		} else if (e->p == e->e) {
			return -1;
		}
		e->bits -= 8;
		*(e->p++) = (uint8_t)(e->value >> e->bits);
	}
}

static ssize_t encode_padding(struct huffman_encoder *e, void *buf) {
	unsigned pad = (8 - (e->bits & 7)) & 7;
	if (pad) {
		uint32_t u = e->value << pad;
		u |= (1 << pad) - 1;
		if (e->p == e->e) {
			return -1;
		}
		*(e->p++) = (uint8_t)u;
	}
	return (size_t)(e->p - (uint8_t*)buf);
}

ssize_t hq_encode_value(void *buf, size_t bufsz, const char *data, size_t len) {
	struct huffman_encoder e;
	e.p = (uint8_t*)buf;
	e.e = e.p + bufsz;
	e.bits = 0;
	e.value = 0;
	for (size_t i = 0; i < len; i++) {
		char ch = data[i];
		if (ch < ' ' || ch > '~' || encode_character(&e, ch)) {
			return -1;
		}
	}
	return encode_padding(&e, buf);
}

ssize_t hq_encode_key(void *buf, size_t bufsz, const char *data, size_t len) {
	struct huffman_encoder e;
	e.p = (uint8_t*)buf;
	e.e = e.p + bufsz;
	e.bits = 0;
	e.value = 0;
	for (size_t i = 0; i < len; i++) {
		char ch = data[i];
		if ('A' <= ch && ch <= 'Z') {
			ch += 'a' - 'A';
		} else if (!('a' <= ch && ch <= 'z') && ch != '-' && !('0' <= ch && ch <= '9')) {
			return -1;
		}
		if (encode_character(&e, ch)) {
			return -1;
		}
	}
	return encode_padding(&e, buf);
}

static const int8_t huf_decode_value[] = {
	-43, -15, -7, -3, -1, '0', '1', -1,
	'2', 'a', -3, -1, 'c', 'e', -1, 'i',
	'o', -11, -3, -1, 's', 't', -3, -1,
	' ', '%', -1, '-', '.', -7, -3, -1,
	'/', '3', -1, '4', '5', -3, -1, '6',
	'7', -1, '8', '9', -35, -15, -7, -3,
	-1, '=', 'A', -1, '_', 'b', -3, -1,
	'd', 'f', -1, 'g', 'h', -7, -3, -1,
	'l', 'm', -1, 'n', 'p', -3, -1, 'r',
	'u', -3, -1, ':', 'B', -1, 'C', 'D',
	-31, -15, -7, -3, -1, 'E', 'F', -1,
	'G', 'H', -3, -1, 'I', 'J', -1, 'K',
	'L', -7, -3, -1, 'M', 'N', -1, 'O',
	'P', -3, -1, 'Q', 'R', -1, 'S', 'T',
	-15, -7, -3, -1, 'U', 'V', -1, 'W',
	'Y', -3, -1, 'j', 'k', -1, 'q', 'v',
	-7, -3, -1, 'w', 'x', -1, 'y', 'z',
	-7, -3, -1, '&', '*', -1, ',', ';',
	-3, -1, 'X', 'Z', -7, -3, -1, '!',
	'"', -1, '(', ')', -5, -1, '?', -1,
	'\'', '+', -5, -1, '|', -1, '#', '>',
	-7, -3, -1, 0, '$', -1, '@', '[',
	-3, -1, ']', '~', -3, -1, '^', '}',
	-3, -1, '<', '`', -1, '{', -7, -5,
	-3, -1, '\\', 0, 0, 0, 0,
};

static const int8_t huf_decode_key[] = {
	-41, -15, -7, -3, -1, '0', '1', -1,
	'2', 'a', -3, -1, 'c', 'e', -1, 'i',
	'o', -9, -3, -1, 's', 't', -1, 0,
	-1, '-', 0, -7, -3, -1, 0, '3',
	-1, '4', '5', -3, -1, '6', '7', -1,
	'8', '9', -31, -13, -5, -1, 0, -1,
	0, 'b', -3, -1, 'd', 'f', -1, 'g',
	'h', -7, -3, -1, 'l', 'm', -1, 'n',
	'p', -3, -1, 'r', 'u', -3, -1, ':',
	0, 0, -1, 0, -9, -1, 0, -3,
	-1, 'j', 'k', -1, 'q', 'v', -7, -3,
	-1, 'w', 'x', -1, 'y', 'z', -1, 0,
	-1, 0, -1, 0, -1, 0, 0,
};

ssize_t hq_decode_value(void *buf, size_t bufsz, const uint8_t *data, size_t len) {
	uint8_t *p = (uint8_t*)buf;
	uint8_t *e = p + bufsz;
	const int8_t *h = huf_decode_value;
	const uint8_t *end = data + len;
	int zeros = 0;
	while (data < end) {
		uint8_t ch = *data;
		uint8_t mask = 0x80;
		while (mask) {
			if (*h < 0) {
				if (ch & mask) {
					h -= *h;
				} else {
					zeros++;
				}
				h++;
				mask >>= 1;
			} else if (*h && p < e) {
				*p++ = *h;
				h = huf_decode_value;
			} else {
				return -1;
			}
		}
		data++;
	}
	if (*h < 0 && !zeros) {
		// padding
	} else if (*h > 0 && p < e) {
		// aligned final byte
		*p++ = *h;
	} else {
		return -1;
	}
	return (size_t)(p - (uint8_t*)buf);
}

int hq_verify_key(const uint8_t *data, size_t len) {
	const int8_t *h = huf_decode_key;
	const uint8_t *end = data + len;
	int zeros = 0;
	while (data < end) {
		uint8_t ch = *data;
		uint8_t mask = 0x80;
		while (mask) {
			if (*h < 0) {
				if (ch & mask) {
					h -= *h;
				} else {
					zeros++;
				}
				h++;
				mask >>= 1;
			} else if (*h) {
				h = huf_decode_key;
				zeros = 0;
			} else {
				return -1;
			}
		}
		data++;
	}
	// check padding
	if (*h == 0 || zeros) {
		return -1;
	}
	return 0;
}

static const uint8_t HUF[] = {
	184, 59, 83, 57, 236, 50, 125, 127,  // :authority
	185, 88, 211, 63,  // :path
	99,  // /
	28, 197,  // age
	7,  // 0
	33, 234, 73, 106, 74, 210, 25, 21, 157, 6, 73, 143, 87,  // content-disposition
	33, 234, 73, 106, 74, 212, 22, 169, 147, 63,  // content-length
	33, 207, 212, 197,  // cookie
	144, 105, 47,  // date
	42, 71, 55,  // etag
	52, 171, 82, 121, 13, 41, 139, 34, 200, 53, 68, 47,  // if-modified-since
	52, 171, 84, 122, 138, 181, 35, 73, 39,  // if-none-match
	160, 104, 74, 212, 158, 67, 74, 98, 201,  // last-modified
	160, 213, 117,  // link
	160, 228, 26, 76, 122, 191,  // location
	176, 178, 150, 194, 217,  // referer
	65, 82, 177, 14, 126, 166, 47,  // set-cookie
	185, 73, 83, 57, 228,  // :method
	189, 171, 78, 156, 23, 183, 255,  // CONNECT
	191, 131, 62, 13, 248, 63,  // DELETE
	197, 131, 127,  // GET
	199, 130, 27, 255,  // HEAD
	213, 175, 126, 77, 90, 119, 127,  // OPTIONS
	215, 171, 118, 255,  // POST
	215, 195, 127,  // PUT
	184, 130, 78, 90, 75,  // :scheme
	157, 41, 175,  // http
	157, 41, 173, 31,  // https
	184, 132, 141, 54, 163,  // :status
	8, 25,  // 103
	16, 1,  // 200
	100, 13, 127,  // 304
	104, 13, 127,  // 404
	108, 12, 255,  // 503
	25, 8, 90, 211,  // accept
	249, 99, 231,  // */*
	29, 117, 208, 98, 13, 38, 61, 76, 73, 82, 22, 164, 168, 64, 230, 47,  // application/dns-message
	25, 8, 90, 210, 177, 106, 33, 228, 53, 83, 127,  // accept-encoding
	155, 217, 171, 250, 82, 66, 203, 64, 210, 95, 165, 35, 179,  // gzip, deflate, br
	25, 8, 90, 210, 181, 131, 170, 98, 163,  // accept-ranges
	143, 210, 74, 143,  // bytes
	25, 8, 84, 33, 98, 30, 164, 216, 122, 22, 29, 20, 31, 194, 211, 148, 114,
	22, 196, 127,  // access-control-allow-headers
	32, 201, 57, 86, 33, 234, 77, 135, 163,  // cache-control
	33, 234, 73, 106, 74, 201, 245, 89, 127,  // content-type
	25, 8, 84, 33, 98, 30, 164, 216, 122, 22, 29, 20, 31, 194, 199, 176, 211,
	26, 175,  // access-control-allow-origin
	249,  // *
	164, 126, 86, 28, 197, 128, 31,  // max-age=0
	164, 126, 86, 28, 197, 128, 77, 190, 32, 0, 31,  // max-age=2592000
	164, 126, 86, 28, 197, 129, 192, 52, 240, 1,  // max-age=604800
	168, 235, 16, 100, 156, 191,  // no-cache
	168, 235, 33, 39, 176, 191,  // no-store
	174, 216, 232, 49, 62, 148, 164, 126, 86, 28, 197, 129, 144, 182, 203, 128, 0,
	63,  // public, max-age=31536000
	33, 234, 73, 106, 74, 197, 168, 135, 144, 213, 77,  // content-encoding
	142, 207,  // br
	155, 217, 171,  // gzip
	29, 117, 208, 98, 13, 38, 61, 76, 116, 31, 113, 160, 150, 26, 180, 255,  // application/javascript
	29, 117, 208, 98, 13, 38, 61, 76, 116, 65, 234,  // application/json
	29, 117, 208, 98, 13, 38, 61, 76, 121, 91, 199, 143, 11, 74, 123, 41, 90,
	219, 40, 45, 68, 60, 133, 147,  // application/x-www-form-urlencoded
	53, 35, 152, 172, 76, 105, 127,  // image/gif
	53, 35, 152, 172, 116, 172, 179, 127,  // image/jpeg
	53, 35, 152, 172, 87, 84, 223,  // image/png
	73, 124, 165, 130, 33, 31,  // text/css
	73, 124, 165, 137, 211, 77, 31, 106, 18, 113, 216, 130, 166, 11, 83, 42, 207,
	127,  // text/html; charset=utf-8
	73, 124, 165, 138, 232, 25, 170,  // text/plain
	73, 124, 165, 138, 232, 25, 170, 251, 36, 227, 177, 5, 76, 22, 166, 85, 158,  // text/plain;charset=utf-8
	176, 117, 76, 95,  // range
	143, 210, 74, 136, 0, 183,  // bytes=0-
	66, 108, 49, 18, 178, 108, 29, 72, 172, 246, 37, 100, 20, 150, 216, 100, 250,  // strict-transport-security
	164, 126, 86, 28, 197, 129, 144, 182, 203, 128, 0, 63,  // max-age=31536000
	164, 126, 86, 28, 197, 129, 144, 182, 203, 128, 0, 62, 212, 53, 68, 162, 217,
	10, 139, 99, 144, 244, 140, 213, 35,  // max-age=31536000; includesubdomains
	164, 126, 86, 28, 197, 129, 144, 182, 203, 128, 0, 62, 212, 53, 68, 162, 217,
	10, 139, 99, 144, 244, 140, 213, 35, 237, 74, 236, 45, 7, 28, 159,  // max-age=31536000; includesubdomains; preload
	238, 59, 61, 127,  // vary
	61, 134, 152, 213, 127,  // origin
	242, 177, 15, 82, 75, 82, 86, 79, 170, 202, 177, 235, 73, 143, 82, 63,  // x-content-type-options
	168, 232, 168, 210, 203,  // nosniff
	242, 183, 148, 33, 106, 236, 58, 74, 68, 152, 245, 127,  // x-xss-protection
	15, 218, 148, 158, 66, 193, 29, 7, 39, 95,  // 1; mode=block
	8, 1,  // 100
	16, 26,  // 204
	16, 28,  // 206
	100, 2,  // 302
	104, 0,  // 400
	104, 12, 255,  // 403
	104, 65,  // 421
	104, 77, 255,  // 425
	108, 0,  // 500
	25, 8, 90, 210, 181, 3, 170, 107, 71, 49, 127,  // accept-language
	25, 8, 84, 33, 98, 30, 164, 216, 122, 22, 29, 20, 31, 194, 196, 176, 178,
	22, 164, 152, 116, 35,  // access-control-allow-credentials
	195, 14, 125, 216, 63,  // FALSE
	223, 183, 134, 15,  // TRUE
	25, 8, 84, 33, 98, 30, 164, 216, 122, 22, 29, 20, 31, 194, 212, 149, 51,
	158, 68, 127,  // access-control-allow-methods
	152, 169,  // get
	152, 169, 250, 82, 179, 161, 63, 74, 30, 180, 152, 245, 35,  // get, post, options
	61, 105, 49, 234, 71,  // options
	25, 8, 84, 33, 98, 30, 164, 216, 122, 22, 47, 154, 206, 130, 173, 57, 71,
	33, 108, 71,  // access-control-expose-headers
	25, 8, 84, 33, 98, 30, 164, 216, 122, 22, 176, 189, 173, 42, 18, 180, 229,
	28, 133, 177, 31,  // access-control-request-headers
	25, 8, 84, 33, 98, 30, 164, 216, 122, 22, 176, 189, 173, 42, 18, 181, 37,
	76, 231, 147,  // access-control-request-method
	172, 232, 79,  // post
	29, 9, 89, 29, 201,  // alt-svc
	37, 5, 29, 159,  // clear
	29, 169, 156, 246, 27, 216, 210, 99, 213,  // authorization
	33, 234, 73, 106, 74, 200, 41, 45, 176, 201, 244, 181, 103, 160, 196, 245,  // content-security-policy
	65, 44, 53, 105, 89, 22, 17, 79, 245, 81, 234, 47, 250, 251, 80, 241, 244,
	41, 18, 178, 44, 34, 159, 234, 163, 212, 95, 245, 246, 164, 99, 65, 86,
	182, 195, 41, 254, 170, 61, 69, 255, 95,  // script-src 'none'; object-src 'none'; base-uri 'none'
	40, 236, 163, 210, 210, 13, 35,  // early-data
	15,  // 1
	47, 154, 202, 68, 172, 68, 255,  // expect-ct
	148, 246, 120, 29, 146, 22, 79,  // forwarded
	52, 171, 88, 58, 166, 47,  // if-range
	174, 219, 43, 58, 11,  // purpose
	174, 194, 202, 84, 146, 127,  // prefetch
	65, 108, 238, 91, 63,  // server
	73, 169, 53, 83, 44, 58, 40, 63, 133, 143, 97, 166, 53, 95,  // timing-allow-origin
	182, 185, 172, 28, 133, 88, 213, 32, 164, 182, 194, 173, 97, 123, 90, 84, 37,
	31,  // upgrade-insecure-requests
	181, 5, 177, 97, 204, 90, 147,  // user-agent
	242, 180, 167, 179, 192, 236, 144, 178, 45, 41, 236,  // x-forwarded-for
	242, 180, 182, 14, 146, 172, 122, 210, 99, 212, 143,  // x-frame-options
	144, 181, 122,  // deny
	64, 233, 41, 236, 52, 198, 171,  // sameorigin
};
const hq_header HQ_AUTHORITY = { HUF + 0, NULL, 0, 8, 2, 0, 0, 1 };
const hq_header HQ_PATH_SLASH = { HUF + 8, HUF + 12, (1 << 2) | 1, 4, 30, 0, 0, 2 };
const hq_header HQ_AGE_0 = { HUF + 13, HUF + 15, (1 << 2) | 1, 2, 26, 0, 0, 3 };
const hq_header HQ_CONTENT_DISPOSITION = { HUF + 16, NULL, 0, 13, 1, 0, 0, 4 };
const hq_header HQ_CONTENT_LENGTH_0 = { HUF + 29, HUF + 15, (1 << 2) | 1, 10, 0, 0, 0, 5 };
const hq_header HQ_COOKIE = { HUF + 39, NULL, 0, 4, 22, 0, 0, 6 };
const hq_header HQ_DATE = { HUF + 43, NULL, 0, 3, 7, 0, 0, 7 };
const hq_header HQ_ETAG = { HUF + 46, NULL, 0, 3, 27, 0, 0, 8 };
const hq_header HQ_IF_MODIFIED_SINCE = { HUF + 49, NULL, 0, 12, 20, 0, 0, 9 };
const hq_header HQ_IF_NONE_MATCH = { HUF + 61, NULL, 0, 9, 0, 0, 0, 10 };
const hq_header HQ_LAST_MODIFIED = { HUF + 70, NULL, 0, 9, 19, 0, 0, 11 };
const hq_header HQ_LINK = { HUF + 79, NULL, 0, 3, 17, 0, 0, 12 };
const hq_header HQ_LOCATION = { HUF + 82, NULL, 0, 6, 24, 0, 0, 13 };
const hq_header HQ_REFERER = { HUF + 88, NULL, 0, 5, 30, 0, 0, 14 };
const hq_header HQ_SET_COOKIE = { HUF + 93, NULL, 0, 7, 22, 0, 0, 15 };
const hq_header HQ_METHOD_CONNECT = { HUF + 100, HUF + 105, (7 << 2) | 1, 5, 1, 0, 0, 16 };
const hq_header HQ_METHOD_DELETE = { HUF + 100, HUF + 112, (6 << 2) | 1, 5, 1, 0, 0, 17 };
const hq_header HQ_METHOD_GET = { HUF + 100, HUF + 118, (3 << 2) | 1, 5, 1, 0, 0, 18 };
const hq_header HQ_METHOD_HEAD = { HUF + 100, HUF + 121, (4 << 2) | 1, 5, 1, 0, 0, 19 };
const hq_header HQ_METHOD_OPTIONS = { HUF + 100, HUF + 125, (7 << 2) | 1, 5, 1, 0, 0, 20 };
const hq_header HQ_METHOD_POST = { HUF + 100, HUF + 132, (4 << 2) | 1, 5, 1, 0, 0, 21 };
const hq_header HQ_METHOD_PUT = { HUF + 100, HUF + 136, (3 << 2) | 1, 5, 1, 0, 0, 22 };
const hq_header HQ_SCHEME_HTTP = { HUF + 139, HUF + 144, (3 << 2) | 1, 5, 16, 0, 0, 23 };
const hq_header HQ_SCHEME_HTTPS = { HUF + 139, HUF + 147, (4 << 2) | 1, 5, 16, 0, 0, 24 };
const hq_header HQ_STATUS_103 = { HUF + 151, HUF + 156, (2 << 2) | 1, 5, 7, 0, 0, 25 };
const hq_header HQ_STATUS_200 = { HUF + 151, HUF + 158, (2 << 2) | 1, 5, 7, 0, 0, 26 };
const hq_header HQ_STATUS_304 = { HUF + 151, HUF + 160, (3 << 2) | 1, 5, 7, 0, 0, 27 };
const hq_header HQ_STATUS_404 = { HUF + 151, HUF + 163, (3 << 2) | 1, 5, 7, 0, 0, 28 };
const hq_header HQ_STATUS_503 = { HUF + 151, HUF + 166, (3 << 2) | 1, 5, 7, 0, 0, 29 };
const hq_header HQ_ACCEPT_STAR_STAR = { HUF + 169, HUF + 173, (3 << 2) | 1, 4, 27, 0, 0, 30 };
const hq_header HQ_ACCEPT_APPLICATION_DNS_MESSAGE = { HUF + 169, HUF + 176, (16 << 2) | 1, 4, 27, 0, 0, 31 };
const hq_header HQ_ACCEPT_ENCODING_GZIP_DEFLATE_BR = { HUF + 192, HUF + 203, (13 << 2) | 1, 11, 3, 0, 0, 32 };
const hq_header HQ_ACCEPT_RANGES_BYTES = { HUF + 216, HUF + 225, (4 << 2) | 1, 9, 9, 0, 0, 33 };
const hq_header HQ_ACCESS_CONTROL_ALLOW_HEADERS_CACHE_CONTROL = { HUF + 229, HUF + 249, (9 << 2) | 1, 20, 29, 0, 0, 34 };
const hq_header HQ_ACCESS_CONTROL_ALLOW_HEADERS_CONTENT_TYPE = { HUF + 229, HUF + 258, (9 << 2) | 1, 20, 29, 0, 0, 35 };
const hq_header HQ_ACCESS_CONTROL_ALLOW_ORIGIN_STAR = { HUF + 267, HUF + 286, (1 << 2) | 1, 19, 22, 0, 0, 36 };
const hq_header HQ_CACHE_CONTROL_MAX_AGE_0 = { HUF + 249, HUF + 287, (7 << 2) | 1, 9, 23, 0, 0, 37 };
const hq_header HQ_CACHE_CONTROL_MAX_AGE_2592000 = { HUF + 249, HUF + 294, (11 << 2) | 1, 9, 23, 0, 0, 38 };
const hq_header HQ_CACHE_CONTROL_MAX_AGE_604800 = { HUF + 249, HUF + 305, (10 << 2) | 1, 9, 23, 0, 0, 39 };
const hq_header HQ_CACHE_CONTROL_NO_CACHE = { HUF + 249, HUF + 315, (6 << 2) | 1, 9, 23, 0, 0, 40 };
const hq_header HQ_CACHE_CONTROL_NO_STORE = { HUF + 249, HUF + 321, (6 << 2) | 1, 9, 23, 0, 0, 41 };
const hq_header HQ_CACHE_CONTROL_PUBLIC_MAX_AGE_31536000 = { HUF + 249, HUF + 327, (18 << 2) | 1, 9, 23, 0, 0, 42 };
const hq_header HQ_CONTENT_ENCODING_BR = { HUF + 345, HUF + 356, (2 << 2) | 1, 11, 13, 0, 0, 43 };
const hq_header HQ_CONTENT_ENCODING_GZIP = { HUF + 345, HUF + 358, (3 << 2) | 1, 11, 13, 0, 0, 44 };
const hq_header HQ_CONTENT_TYPE_APPLICATION_DNS_MESSAGE = { HUF + 258, HUF + 176, (16 << 2) | 1, 9, 15, 0, 0, 45 };
const hq_header HQ_CONTENT_TYPE_APPLICATION_JAVASCRIPT = { HUF + 258, HUF + 361, (16 << 2) | 1, 9, 15, 0, 0, 46 };
const hq_header HQ_CONTENT_TYPE_APPLICATION_JSON = { HUF + 258, HUF + 377, (11 << 2) | 1, 9, 15, 0, 0, 47 };
const hq_header HQ_CONTENT_TYPE_APPLICATION_X_WWW_FORM_URLENCODED = { HUF + 258, HUF + 388, (24 << 2) | 1, 9, 15, 0, 0, 48 };
const hq_header HQ_CONTENT_TYPE_IMAGE_GIF = { HUF + 258, HUF + 412, (7 << 2) | 1, 9, 15, 0, 0, 49 };
const hq_header HQ_CONTENT_TYPE_IMAGE_JPEG = { HUF + 258, HUF + 419, (8 << 2) | 1, 9, 15, 0, 0, 50 };
const hq_header HQ_CONTENT_TYPE_IMAGE_PNG = { HUF + 258, HUF + 427, (7 << 2) | 1, 9, 15, 0, 0, 51 };
const hq_header HQ_CONTENT_TYPE_TEXT_CSS = { HUF + 258, HUF + 434, (6 << 2) | 1, 9, 15, 0, 0, 52 };
const hq_header HQ_CONTENT_TYPE_TEXT_HTML_CHARSET_UTF_8 = { HUF + 258, HUF + 440, (18 << 2) | 1, 9, 15, 0, 0, 53 };
const hq_header HQ_CONTENT_TYPE_TEXT_PLAIN = { HUF + 258, HUF + 458, (7 << 2) | 1, 9, 15, 0, 0, 54 };
const hq_header HQ_CONTENT_TYPE_TEXT_PLAIN_CHARSET_UTF_8 = { HUF + 258, HUF + 465, (17 << 2) | 1, 9, 15, 0, 0, 55 };
const hq_header HQ_RANGE_BYTES_0_ = { HUF + 482, HUF + 486, (6 << 2) | 1, 4, 27, 0, 0, 56 };
const hq_header HQ_STRICT_TRANSPORT_SECURITY_MAX_AGE_31536000 = { HUF + 492, HUF + 509, (12 << 2) | 1, 17, 4, 0, 0, 57 };
const hq_header HQ_STRICT_TRANSPORT_SECURITY_MAX_AGE_31536000_INCLUDESUBDOMAINS = { HUF + 492, HUF + 521, (25 << 2) | 1, 17, 4, 0, 0, 58 };
const hq_header HQ_STRICT_TRANSPORT_SECURITY_MAX_AGE_31536000_INCLUDESUBDOMAINS_PRELOAD = { HUF + 492, HUF + 546, (32 << 2) | 1, 17, 4, 0, 0, 59 };
const hq_header HQ_VARY_ACCEPT_ENCODING = { HUF + 578, HUF + 192, (11 << 2) | 1, 4, 18, 0, 0, 60 };
const hq_header HQ_VARY_ORIGIN = { HUF + 578, HUF + 582, (5 << 2) | 1, 4, 18, 0, 0, 61 };
const hq_header HQ_X_CONTENT_TYPE_OPTIONS_NOSNIFF = { HUF + 587, HUF + 603, (5 << 2) | 1, 16, 16, 0, 0, 62 };
const hq_header HQ_X_XSS_PROTECTION_1_MODE_BLOCK = { HUF + 608, HUF + 620, (10 << 2) | 1, 12, 27, 0, 0, 63 };
const hq_header HQ_STATUS_100 = { HUF + 151, HUF + 630, (2 << 2) | 1, 5, 7, 0, 0, 64 };
const hq_header HQ_STATUS_204 = { HUF + 151, HUF + 632, (2 << 2) | 1, 5, 7, 0, 0, 65 };
const hq_header HQ_STATUS_206 = { HUF + 151, HUF + 634, (2 << 2) | 1, 5, 7, 0, 0, 66 };
const hq_header HQ_STATUS_302 = { HUF + 151, HUF + 636, (2 << 2) | 1, 5, 7, 0, 0, 67 };
const hq_header HQ_STATUS_400 = { HUF + 151, HUF + 638, (2 << 2) | 1, 5, 7, 0, 0, 68 };
const hq_header HQ_STATUS_403 = { HUF + 151, HUF + 640, (3 << 2) | 1, 5, 7, 0, 0, 69 };
const hq_header HQ_STATUS_421 = { HUF + 151, HUF + 643, (2 << 2) | 1, 5, 7, 0, 0, 70 };
const hq_header HQ_STATUS_425 = { HUF + 151, HUF + 645, (3 << 2) | 1, 5, 7, 0, 0, 71 };
const hq_header HQ_STATUS_500 = { HUF + 151, HUF + 648, (2 << 2) | 1, 5, 7, 0, 0, 72 };
const hq_header HQ_ACCEPT_LANGUAGE = { HUF + 650, NULL, 0, 11, 0, 0, 0, 73 };
const hq_header HQ_ACCESS_CONTROL_ALLOW_CREDENTIALS_FALSE = { HUF + 661, HUF + 683, (5 << 2) | 1, 22, 14, 0, 0, 74 };
const hq_header HQ_ACCESS_CONTROL_ALLOW_CREDENTIALS_TRUE = { HUF + 661, HUF + 688, (4 << 2) | 1, 22, 14, 0, 0, 75 };
const hq_header HQ_ACCESS_CONTROL_ALLOW_HEADERS_STAR = { HUF + 229, HUF + 286, (1 << 2) | 1, 20, 29, 0, 0, 76 };
const hq_header HQ_ACCESS_CONTROL_ALLOW_METHODS_GET = { HUF + 692, HUF + 712, (2 << 2) | 1, 20, 4, 0, 0, 77 };
const hq_header HQ_ACCESS_CONTROL_ALLOW_METHODS_GET_POST_OPTIONS = { HUF + 692, HUF + 714, (13 << 2) | 1, 20, 4, 0, 0, 78 };
const hq_header HQ_ACCESS_CONTROL_ALLOW_METHODS_OPTIONS = { HUF + 692, HUF + 727, (5 << 2) | 1, 20, 4, 0, 0, 79 };
const hq_header HQ_ACCESS_CONTROL_EXPOSE_HEADERS_CONTENT_LENGTH = { HUF + 732, HUF + 29, (10 << 2) | 1, 20, 5, 0, 0, 80 };
const hq_header HQ_ACCESS_CONTROL_REQUEST_HEADERS_CONTENT_TYPE = { HUF + 752, HUF + 258, (9 << 2) | 1, 21, 7, 0, 0, 81 };
const hq_header HQ_ACCESS_CONTROL_REQUEST_METHOD_GET = { HUF + 773, HUF + 712, (2 << 2) | 1, 20, 17, 0, 0, 82 };
const hq_header HQ_ACCESS_CONTROL_REQUEST_METHOD_POST = { HUF + 773, HUF + 793, (3 << 2) | 1, 20, 17, 0, 0, 83 };
const hq_header HQ_ALT_SVC_CLEAR = { HUF + 796, HUF + 801, (4 << 2) | 1, 5, 16, 0, 0, 84 };
const hq_header HQ_AUTHORIZATION = { HUF + 805, NULL, 0, 9, 4, 0, 0, 85 };
const hq_header HQ_CONTENT_SECURITY_POLICY_SCRIPT_SRC_NONE_OBJECT_SRC_NONE_BASE_URI_NONE = { HUF + 814, HUF + 830, (42 << 2) | 1, 16, 25, 0, 0, 86 };
const hq_header HQ_EARLY_DATA_1 = { HUF + 872, HUF + 879, (1 << 2) | 1, 7, 18, 0, 0, 87 };
const hq_header HQ_EXPECT_CT = { HUF + 880, NULL, 0, 7, 15, 0, 0, 88 };
const hq_header HQ_FORWARDED = { HUF + 887, NULL, 0, 7, 21, 0, 0, 89 };
const hq_header HQ_IF_RANGE = { HUF + 894, NULL, 0, 6, 21, 0, 0, 90 };
const hq_header HQ_ORIGIN = { HUF + 582, NULL, 0, 5, 18, 0, 0, 91 };
const hq_header HQ_PURPOSE_PREFETCH = { HUF + 900, HUF + 905, (6 << 2) | 1, 5, 12, 0, 0, 92 };
const hq_header HQ_SERVER = { HUF + 911, NULL, 0, 5, 20, 0, 0, 93 };
const hq_header HQ_TIMING_ALLOW_ORIGIN_STAR = { HUF + 916, HUF + 286, (1 << 2) | 1, 14, 15, 0, 0, 94 };
const hq_header HQ_UPGRADE_INSECURE_REQUESTS_1 = { HUF + 930, HUF + 879, (1 << 2) | 1, 18, 17, 0, 0, 95 };
const hq_header HQ_USER_AGENT = { HUF + 948, NULL, 0, 7, 12, 0, 0, 96 };
const hq_header HQ_X_FORWARDED_FOR = { HUF + 955, NULL, 0, 11, 31, 0, 0, 97 };
const hq_header HQ_X_FRAME_OPTIONS_DENY = { HUF + 966, HUF + 977, (3 << 2) | 1, 11, 23, 0, 0, 98 };
const hq_header HQ_X_FRAME_OPTIONS_SAMEORIGIN = { HUF + 966, HUF + 980, (7 << 2) | 1, 11, 23, 0, 0, 99 };