#include "qpack.h"
#include <cutils/endian.h>
#include <stdint.h>


struct huffman_encoding {
	uint32_t value : 24;
	uint32_t bits : 8;
};

static struct huffman_encoding huffman[] = {
	{ 0x14, 6},    // ' ' (32)  | 010100
	{ 0x3F8, 10},  // '!' (33)  | 11111110
	{ 0x3f9, 10},  // '"' (34)  | 1111111001
	{ 0xffa, 12},  // '#' (35)  | 111111111010
	{ 0x1ff9, 13}, // '$' (36)  | 1111111111001
	{ 0x15, 6},    // '%' (37)  | 010101
	{ 0xf8, 8},    // '&' (38)  | 11111000
	{ 0x7fa, 11},  // ''' (39)  | 11111111010
	{ 0x3fa, 10},  // '(' (40)  | 1111111010
	{ 0x3fb, 10},  // ')' (41)  | 1111111011
	{ 0xf9, 8},    // '*' (42)  | 11111001
	{ 0x7fb, 11},  // '+' (43)  | 11111111011
	{ 0xfa, 8},    // ',' (44)  | 11111010
	{ 0x16, 6},    // '-' (45)  | 010110
	{ 0x17, 6},    // '.' (46)  | 010111
	{ 0x18, 6},    // '/' (47)  | 011000
	{ 0x0, 5},     // '0' (48)  | 00000
	{ 0x1, 5},     // '1' (49)  | 00001
	{ 0x2, 5},     // '2' (50)  | 00010
	{ 0x19, 6},    // '3' (51)  | 011001
	{ 0x1a, 6},    // '4' (52)  | 011010
	{ 0x1b, 6},    // '5' (53)  | 011011
	{ 0x1c, 6},    // '6' (54)  | 011100
	{ 0x1d, 6},    // '7' (55)  | 011101
	{ 0x1e, 6},    // '8' (56)  | 011110
	{ 0x1f, 6},    // '9' (57)  | 011111
	{ 0x5c, 7},    // ':' (58)  | 1011100
	{ 0xfb, 8},    // ';' (59)  | 11111011
	{ 0x7ffc, 15}, // '<' (60)  | 111111111111100
	{ 0x20, 6},    // '=' (61)  | 100000
	{ 0xffb, 12},  // '>' (62)  | 111111111011
	{ 0x3fc, 10},  // '?' (63)  | 1111111100
	{ 0x1ffa, 13}, // '@' (64)  | 1111111111010
	{ 0x21, 6},    // 'A' (65)  | 100001
	{ 0x5d, 7},    // 'B' (66)  | 1011101
	{ 0x5e, 7},    // 'C' (67)  | 1011110
	{ 0x5f, 7},    // 'D' (68)  | 1011111
	{ 0x60, 7},    // 'E' (69)  | 1100000
	{ 0x61, 7},    // 'F' (70)  | 1100001
	{ 0x62, 7},    // 'G' (71)  | 1100010
	{ 0x63, 7},    // 'H' (72)  | 1100011
	{ 0x64, 7},    // 'I' (73)  | 1100100
	{ 0x65, 7},    // 'J' (74)  | 1100101
	{ 0x66, 7},    // 'K' (75)  | 1100110
	{ 0x67, 7},    // 'L' (76)  | 1100111
	{ 0x68, 7},    // 'M' (77)  | 1101000
	{ 0x69, 7},    // 'N' (78)  | 1101001
	{ 0x6a, 7},    // 'O' (79)  | 1101010
	{ 0x6b, 7},    // 'P' (80)  | 1101011
	{ 0x6c, 7},    // 'Q' (81)  | 1101100
	{ 0x6d, 7},    // 'R' (82)  | 1101101
	{ 0x6e, 7},    // 'S' (83)  | 1101110
	{ 0x6f, 7},    // 'T' (84)  | 1101111
	{ 0x70, 7},    // 'U' (85)  | 1110000
	{ 0x71, 7},    // 'V' (86)  | 1110001
	{ 0x72, 7},    // 'W' (87)  | 1110010
	{ 0xfc, 8},    // 'X' (88)  | 11111100
	{ 0x73, 7},    // 'Y' (89)  | 1110011
	{ 0xfd, 8},    // 'Z' (90)  | 11111101
	{ 0x1ffb, 13}, // '[' (91)  | 1111111111011
	{ 0x7fff0, 19},// '\' (92)  | 1111111111111110000
	{ 0x1ffc, 13}, // ']' (93)  | 1111111111100
	{ 0x3ffc, 14}, // '^' (94)  | 11111111111100
	{ 0x22, 6},    // '_' (95)  | 100010
	{ 0x7ffd, 15}, // '`' (96)  | 111111111111101
	{ 0x3, 5},     // 'a' (97)  | 00011
	{ 0x23, 6},    // 'b' (98)  | 100011
	{ 0x4, 5},     // 'c' (99)  | 00100
	{ 0x24, 6},    // 'd' (100) | 100100
	{ 0x5, 5},     // 'e' (101) | 00101
	{ 0x25, 6},    // 'f' (102) | 100101
	{ 0x26, 6},    // 'g' (103) | 100110
	{ 0x27, 6},    // 'h' (104) | 100111
	{ 0x6, 5},     // 'i' (105) | 00110
	{ 0x74, 7},    // 'j' (106) | 1110100
	{ 0x75, 7},    // 'k' (107) | 1110101
	{ 0x28, 6},    // 'l' (108) | 101000
	{ 0x29, 6},    // 'm' (109) | 101001
	{ 0x2a, 6},    // 'n' (110) | 101010
	{ 0x7, 5},     // 'o' (111) | 00111
	{ 0x2b, 6},    // 'p' (112) | 101011
	{ 0x76, 7},    // 'q' (113) | 1110110
	{ 0x2c, 6},    // 'r' (114) | 101100
	{ 0x8, 5},     // 's' (115) | 01000
	{ 0x9, 5},     // 't' (116) | 01001
	{ 0x2d, 6},    // 'u' (117) | 101101
	{ 0x77, 7},    // 'v' (118) | 1110111
	{ 0x78, 7},    // 'w' (119) | 1111000
	{ 0x79, 7},    // 'x' (120) | 1111001
	{ 0x7a, 7},    // 'y' (121) | 1111010
	{ 0x7b, 7},    // 'z' (122) | 1111011
	{ 0x7ffe, 15}, // '{' (123) | 111111111111110
	{ 0x7fc, 11},  // '|' (124) | 11111111100
	{ 0x3ffd, 14}, // '}' (125) | 11111111111101
	{ 0x1ffd, 13}, // '~' (126) | 1111111111101
};

ssize_t hq_huffman_encode(qslice_t *s, const char *data, size_t len) {
	uint32_t bits = 0;
	uint8_t *start = s->p;
	uint32_t u = 0;
	for (size_t i = 0; i < len; i++) {
		uint8_t ch = ((uint8_t*)data)[i];
		if (ch < ' ' || ch > '~') {
			return -1;
		}

		struct huffman_encoding e = huffman[ch - ' '];
		u <<= e.bits;
		u |= e.value;
		bits += e.bits;
		while (bits >= 8) {
			bits -= 8;
			*(s->p++) = (uint8_t)(u >> bits);
			if (s->p == s->e) {
				return -1;
			}
		}
	}
	// finish out padding as a series of 1 bits
	unsigned pad = (8 - (bits & 7)) & 7;
	if (pad) {
		u <<= pad;
		u |= (1 << pad) - 1;
		*(s->p++) = (uint8_t)u;
	}
	return (int)(s->p - start);
}

static uint16_t read_bits(uint8_t *p, uint16_t off, unsigned bitsz) {
	uint16_t mask = (1 << bitsz) - 1;
	uint32_t bit = (uint32_t)off * bitsz;
	uint16_t u = little_16(p + (bit >> 3));
	uint8_t shift = (uint8_t)(bit & 7);
	return (u >> shift) & mask;
}

static void write_bits(uint8_t *p, uint16_t off, uint16_t value, unsigned bitsz) {
	uint16_t mask = (1 << bitsz) - 1;
	uint32_t bit = (uint32_t)off * bitsz;
	assert((value & ~mask) == 0);
	uint16_t u = little_16(p + (bit >> 3));
	uint8_t shift = (uint8_t)(bit & 7);
	u &= ~(mask << shift);
	u |= value << shift;
	write_little_16(p + (bit >> 3), u);
}

struct node {
	struct node *child[2];
	uint8_t value;
};

static uint16_t write_node(uint8_t *p, uint16_t off, const struct node *n, unsigned bitsz) {
	uint16_t flag = 1 << (bitsz - 1);
	assert(off < UINT16_MAX);
	if (!n) {
		write_bits(p, off, 0, bitsz);
		return off + 1;
	} else if (n->value) {
		write_bits(p, off, n->value | flag, bitsz);
		return off + 1;
	} else {
		uint16_t right = write_node(p, off + 1, n->child[0], bitsz);
		assert(right - off < flag);
		write_bits(p, off, right - off, bitsz);
		return write_node(p, right, n->child[1], bitsz);
	}
}

size_t hq_generate_decoder(uint8_t *buf) {
	struct node nodes[1024], *next = nodes;
	struct node *root = next++;
	memset(nodes, 0, sizeof(nodes));

	for (size_t i = 0; i < sizeof(huffman) / sizeof(huffman[0]); i++) {
		uint32_t bits = huffman[i].bits;
		uint32_t value = huffman[i].value;
		struct node *p = root;
		while (bits) {
			int bit = (value >> (--bits)) & 1;
			struct node **c = &p->child[bit];
			if (!*c) {
				assert(next < nodes + 1024);
				*c = next++;
			}
			p = *c;
			assert(!p->value);
		}
		p->value = (uint8_t)(i + ' ');
	}

	return write_node(buf, 0, root, 8);
}

ssize_t hq_huffman_decode(qslice_t *s, const uint8_t *data, size_t len) {
	uint8_t buf[256];
	hq_generate_decoder(buf);
	size_t i = 0;
	while (i < len * 8) {
		uint8_t *p = buf;
		while (i < len * 8 && !(*p & 0x80)) {
			if (data[len >> 3] & (1 << (len & 7))) {
				p += *p;
			} else {
				p++;
			}
			
		}
		*(s->p++) = *p;
	}
	return -1;
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

static const hq_dict_entry_t entries[] = {
        { 0, 8, 0, 0 },
        { 8, 4, 12, 1 },
        { 13, 2, 15, 1 },
        { 16, 13, 0, 0 },
        { 29, 10, 15, 1 },
        { 39, 4, 0, 0 },
        { 43, 3, 0, 0 },
        { 46, 3, 0, 0 },
        { 49, 12, 0, 0 },
        { 61, 9, 0, 0 },
        { 70, 9, 0, 0 },
        { 79, 3, 0, 0 },
        { 82, 6, 0, 0 },
        { 88, 5, 0, 0 },
        { 93, 7, 0, 0 },
        { 100, 5, 105, 7 },
        { 100, 5, 112, 6 },
        { 100, 5, 118, 3 },
        { 100, 5, 121, 4 },
        { 100, 5, 125, 7 },
        { 100, 5, 132, 4 },
        { 100, 5, 136, 3 },
        { 139, 5, 144, 3 },
        { 139, 5, 147, 4 },
        { 151, 5, 156, 2 },
        { 151, 5, 158, 2 },
        { 151, 5, 160, 3 },
        { 151, 5, 163, 3 },
        { 151, 5, 166, 3 },
        { 169, 4, 173, 3 },
        { 169, 4, 176, 16 },
        { 192, 11, 203, 13 },
        { 216, 9, 225, 4 },
        { 229, 20, 249, 9 },
        { 229, 20, 258, 9 },
        { 267, 19, 286, 1 },
        { 249, 9, 287, 7 },
        { 249, 9, 294, 11 },
        { 249, 9, 305, 10 },
        { 249, 9, 315, 6 },
        { 249, 9, 321, 6 },
        { 249, 9, 327, 18 },
        { 345, 11, 356, 2 },
        { 345, 11, 358, 3 },
        { 258, 9, 176, 16 },
        { 258, 9, 361, 16 },
        { 258, 9, 377, 11 },
        { 258, 9, 388, 24 },
        { 258, 9, 412, 7 },
        { 258, 9, 419, 8 },
        { 258, 9, 427, 7 },
        { 258, 9, 434, 6 },
        { 258, 9, 440, 18 },
        { 258, 9, 458, 7 },
        { 258, 9, 465, 17 },
        { 482, 4, 486, 6 },
        { 492, 17, 509, 12 },
        { 492, 17, 521, 25 },
        { 492, 17, 546, 32 },
        { 578, 4, 192, 11 },
        { 578, 4, 582, 5 },
        { 587, 16, 603, 5 },
        { 608, 12, 620, 10 },
        { 151, 5, 630, 2 },
        { 151, 5, 632, 2 },
        { 151, 5, 634, 2 },
        { 151, 5, 636, 2 },
        { 151, 5, 638, 2 },
        { 151, 5, 640, 3 },
        { 151, 5, 643, 2 },
        { 151, 5, 645, 3 },
        { 151, 5, 648, 2 },
        { 650, 11, 0, 0 },
        { 661, 22, 683, 5 },
        { 661, 22, 688, 4 },
        { 229, 20, 286, 1 },
        { 692, 20, 712, 2 },
        { 692, 20, 714, 13 },
        { 692, 20, 727, 5 },
        { 732, 20, 29, 10 },
        { 752, 21, 258, 9 },
        { 773, 20, 712, 2 },
        { 773, 20, 793, 3 },
        { 796, 5, 801, 4 },
        { 805, 9, 0, 0 },
        { 814, 16, 830, 42 },
        { 872, 7, 879, 1 },
        { 880, 7, 0, 0 },
        { 887, 7, 0, 0 },
        { 894, 6, 0, 0 },
        { 582, 5, 0, 0 },
        { 900, 5, 905, 6 },
        { 911, 5, 0, 0 },
        { 916, 14, 286, 1 },
        { 930, 18, 879, 1 },
        { 948, 7, 0, 0 },
        { 955, 11, 0, 0 },
        { 966, 11, 977, 3 },
        { 966, 11, 980, 7 },
};

const hq_dictionary_t HQ_STATIC_DICT = { HUF, entries, 99, 0, 0, 99 };

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

int hq_decode_header(qslice_t *s, qslice_t *buf, const hq_dictionary_t *dict, hq_header_t *h) {
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
		h->never_compress = false;
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
		h->never_compress = (hdr & LITERAL_BOTH_NEVER) != 0;
		h->key = dict->data + e->name_off;
		h->key_len = e->name_len;
		return 0;

	} else if (hdr & LITERAL_BOTH) {
		h->never_compress = (hdr & LITERAL_BOTH_NEVER) != 0;
		return read_literal(s, LITERAL_BOTH_NAME, buf, &h->key, &h->key_len)
			|| read_literal(s, LITERAL_BOTH_VALUE, buf, &h->value, &h->value_len);

	} else if (hdr & INDEX_POST) {
		const hq_dict_entry_t *e = lookup_entry(s, INDEX_POST_INDEX, dict, false, NULL);
		if (!e) {
			return -1;
		}
		h->never_compress = false;
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
		h->never_compress = false;
		h->key = dict->data + e->name_off;
		h->key_len = e->name_len;
		return 0;
	}
}

