#include "qpack.h"
#include <cutils/test.h>
#include <cutils/str.h>
#include <cutils/hash.h>
#include <cutils/vector.h>
#include <ctype.h>

struct csym {
	unsigned off;
	unsigned sz;
	str_t c;
};


static void print_huffman(log_t *log, const char *value, struct csym *sym) {
	static unsigned offset;
	uint8_t buf[128];
	qslice_t s = { buf, buf + sizeof(buf) };
	ssize_t sz = hq_huffman_encode(&s, value, strlen(value));
	EXPECT_GT(sz, 0);
	sym->c = str_init("_");
	if (!strcmp(value, "/")) {
		str_add(&sym->c, "SLASH");
	} else if (!strcmp(value, "*/*")) {
		str_add(&sym->c, "STAR_STAR");
	} else {
		for (size_t i = 0; value[i]; i++) {
			char ch = value[i];
			if (ch == ':' || ch == '\'' || ((ch == ';' || ch == ',') && value[i + 1] == ' ')) {
				continue;
			} else if ('a' <= ch && ch <= 'z') {
				str_addch(&sym->c, ch - 'a' + 'A');
			} else if (('A' <= ch && ch <= 'Z') || ('0' <= ch && ch <= '9')) {
				str_addch(&sym->c, ch);
			} else if (ch == '*') {
				str_add(&sym->c, "STAR");
			} else {
				str_addch(&sym->c, '_');
			}
		}
	}
	str_t data = STR_INIT;
	for (ssize_t i = 0; i < sz; i++) {
		str_addf(&data, "%d,%s", buf[i], (i && !(i&15) && (i+1) < sz) ? "\n\t" : " ");
	}
	LOG(log, "\t%s // %s", data.c_str, value);
	str_destroy(&data);
	sym->off = offset;
	sym->sz = (unsigned)sz;
	offset += sym->sz;
}

static struct {
	hash_t h;
	blob_t *keys;
	struct csym *values;
} symbols;

struct header {
	int index;
	const char *key, *value;
};
static struct {
	struct header *v;
	size_t size, cap;
} headers;

static size_t rawlen;

static void insert_header(log_t *log, int index, const char *key, const char *value) {
	assert(index == (int)headers.size);
	struct header *h = APPEND_ZERO(&headers);
	h->index = index;

	bool added;
	size_t idx = INSERT_BLOB_HASH(&symbols, key, strlen(key), &added);
	if (added) {
		print_huffman(log, key, &symbols.values[idx]);
	}
	h->key = key;

	if (*value) {
		idx = INSERT_BLOB_HASH(&symbols, value, strlen(value), &added);
		if (added) {
			print_huffman(log, value, &symbols.values[idx]);
		}
		h->value = value;
	}
	rawlen += strlen(key) + strlen(value);
}

static void print_dictionary(log_t *log) {
	LOG(log, "static const hq_dict_entry_t entries[] = {");
	for (size_t i = 0; i < headers.size; i++) {
		struct header *h = &headers.v[i];
		struct csym *k = &symbols.values[FIND_BLOB_HASH(&symbols, h->key, strlen(h->key))];
		struct csym *v = h->value ? &symbols.values[FIND_BLOB_HASH(&symbols, h->value, strlen(h->value))] : NULL;
		LOG(log, "\t{ %u, %u, %u, %u },", k->off, k->sz, v ? v->off : 0, v ? v->sz : 0);
	}
	LOG(log, "};");
	LOG(log, "");
	LOG(log, "const hq_dictionary_t HQ_STATIC_DICT = { HUF, entries, %u, 0, 0, %u };", (unsigned)headers.size, (unsigned)headers.size);
}

static void print_headers(log_t *log, bool declare) {
	for (size_t i = 0; i < headers.size; i++) {
		struct header *h = &headers.v[i];
		struct csym *k = &symbols.values[FIND_BLOB_HASH(&symbols, h->key, strlen(h->key))];
		struct csym *v = h->value ? &symbols.values[FIND_BLOB_HASH(&symbols, h->value, strlen(h->value))] : NULL;

		if (declare) {
			LOG(log, "extern const hq_header_t HQ%s%s;", k->c.c_str, v ? v->c.c_str : "");
		} else if (v) {
			LOG(log, "const hq_header_t HQ%s%s = { %d, %u, %u, false, HUF+%u, HUF+%u };", k->c.c_str, v->c.c_str, h->index, k->sz, v->sz, k->off, v->off);
		} else {
			LOG(log, "const hq_header_t HQ%s = { %d, %u, 0, false, HUF+%u, NULL };", k->c.c_str, h->index, k->sz, k->off);
		}
	}
}

int main(int argc, const char *argv[]) {
	log_t *log = start_test(argc, argv);

	uint8_t buf[HDR_MAX_SIZE];
	qslice_t sbuf = { buf, buf + sizeof(buf) };
	uint8_t custom_key[] = { 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f };
	EXPECT_EQ(sizeof(custom_key), hq_huffman_encode(&sbuf, "custom-key", strlen("custom-key")));
	EXPECT_BYTES_EQ(custom_key, sizeof(custom_key), buf, sizeof(custom_key));

	LOG(log, "static const uint8_t HUF[] = {");
	insert_header(log, 0, ":authority", "");
	insert_header(log, 1, ":path", "/");
	insert_header(log, 2, "age", "0");
	insert_header(log, 3, "content-disposition", "");
	insert_header(log, 4, "content-length", "0");
	insert_header(log, 5, "cookie", "");
	insert_header(log, 6, "date", "");
	insert_header(log, 7, "etag", "");
	insert_header(log, 8, "if-modified-since", "");
	insert_header(log, 9, "if-none-match", "");
	insert_header(log, 10, "last-modified", "");
	insert_header(log, 11, "link", "");
	insert_header(log, 12, "location", "");
	insert_header(log, 13, "referer", "");
	insert_header(log, 14, "set-cookie", "");
	insert_header(log, 15, ":method", "CONNECT");
	insert_header(log, 16, ":method", "DELETE");
	insert_header(log, 17, ":method", "GET");
	insert_header(log, 18, ":method", "HEAD");
	insert_header(log, 19, ":method", "OPTIONS");
	insert_header(log, 20, ":method", "POST");
	insert_header(log, 21, ":method", "PUT");
	insert_header(log, 22, ":scheme", "http");
	insert_header(log, 23, ":scheme", "https");
	insert_header(log, 24, ":status", "103");
	insert_header(log, 25, ":status", "200");
	insert_header(log, 26, ":status", "304");
	insert_header(log, 27, ":status", "404");
	insert_header(log, 28, ":status", "503");
	insert_header(log, 29, "accept", "*/*");
	insert_header(log, 30, "accept", "application/dns-message");
	insert_header(log, 31, "accept-encoding", "gzip, deflate, br");
	insert_header(log, 32, "accept-ranges", "bytes");
	insert_header(log, 33, "access-control-allow-headers", "cache-control");
	insert_header(log, 34, "access-control-allow-headers", "content-type");
	insert_header(log, 35, "access-control-allow-origin", "*");
	insert_header(log, 36, "cache-control", "max-age=0");
	insert_header(log, 37, "cache-control", "max-age=2592000");
	insert_header(log, 38, "cache-control", "max-age=604800");
	insert_header(log, 39, "cache-control", "no-cache");
	insert_header(log, 40, "cache-control", "no-store");
	insert_header(log, 41, "cache-control", "public, max-age=31536000");
	insert_header(log, 42, "content-encoding", "br");
	insert_header(log, 43, "content-encoding", "gzip");
	insert_header(log, 44, "content-type", "application/dns-message");
	insert_header(log, 45, "content-type", "application/javascript");
	insert_header(log, 46, "content-type", "application/json");
	insert_header(log, 47, "content-type", "application/x-www-form-urlencoded");
	insert_header(log, 48, "content-type", "image/gif");
	insert_header(log, 49, "content-type", "image/jpeg");
	insert_header(log, 50, "content-type", "image/png");
	insert_header(log, 51, "content-type", "text/css");
	insert_header(log, 52, "content-type", "text/html; charset=utf-8");
	insert_header(log, 53, "content-type", "text/plain");
	insert_header(log, 54, "content-type", "text/plain;charset=utf-8");
	insert_header(log, 55, "range", "bytes=0-");
	insert_header(log, 56, "strict-transport-security", "max-age=31536000");
	insert_header(log, 57, "strict-transport-security", "max-age=31536000; includesubdomains");
	insert_header(log, 58, "strict-transport-security", "max-age=31536000; includesubdomains; preload");
	insert_header(log, 59, "vary", "accept-encoding");
	insert_header(log, 60, "vary", "origin");
	insert_header(log, 61, "x-content-type-options", "nosniff");
	insert_header(log, 62, "x-xss-protection", "1; mode=block");
	insert_header(log, 63, ":status", "100");
	insert_header(log, 64, ":status", "204");
	insert_header(log, 65, ":status", "206");
	insert_header(log, 66, ":status", "302");
	insert_header(log, 67, ":status", "400");
	insert_header(log, 68, ":status", "403");
	insert_header(log, 69, ":status", "421");
	insert_header(log, 70, ":status", "425");
	insert_header(log, 71, ":status", "500");
	insert_header(log, 72, "accept-language", "");
	insert_header(log, 73, "access-control-allow-credentials", "FALSE");
	insert_header(log, 74, "access-control-allow-credentials", "TRUE");
	insert_header(log, 75, "access-control-allow-headers", "*");
	insert_header(log, 76, "access-control-allow-methods", "get");
	insert_header(log, 77, "access-control-allow-methods", "get, post, options");
	insert_header(log, 78, "access-control-allow-methods", "options");
	insert_header(log, 79, "access-control-expose-headers", "content-length");
	insert_header(log, 80, "access-control-request-headers", "content-type");
	insert_header(log, 81, "access-control-request-method", "get");
	insert_header(log, 82, "access-control-request-method", "post");
	insert_header(log, 83, "alt-svc", "clear");
	insert_header(log, 84, "authorization", "");
	insert_header(log, 85, "content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'");
	insert_header(log, 86, "early-data", "1");
	insert_header(log, 87, "expect-ct", "");
	insert_header(log, 88, "forwarded", "");
	insert_header(log, 89, "if-range", "");
	insert_header(log, 90, "origin", "");
	insert_header(log, 91, "purpose", "prefetch");
	insert_header(log, 92, "server", "");
	insert_header(log, 93, "timing-allow-origin", "*");
	insert_header(log, 94, "upgrade-insecure-requests", "1");
	insert_header(log, 95, "user-agent", "");
	insert_header(log, 96, "x-forwarded-for", "");
	insert_header(log, 97, "x-frame-options", "deny");
	insert_header(log, 98, "x-frame-options", "sameorigin");
	LOG(log, "};");

	LOG(log, "");
	print_dictionary(log);
	LOG(log, "");
	print_headers(log, false);
	LOG(log, "");
	LOG(log, "extern const hq_dictionary_t HQ_STATIC_DICT;");
	LOG(log, "");
	print_headers(log, true);

	uint8_t bigbuf[4096];
	size_t decsz = hq_generate_decoder((int8_t*)bigbuf);
	LOG(log, "");
	LOG(log, "static const int8_t huf_decoder[] = {");
	for (size_t i = 0; i < decsz; i += 8) {
		struct {
			size_t len;
			char c_str[256];
		} s;
		s.len = 0;
		for (size_t j = i; j < i + 8 && j < decsz; j++) {
			ca_addf(&s, "%c%d,", (j & 7) ? ' ' : '\t', ((int8_t*)bigbuf)[j]);
		}
		LOG(log, "%s", s.c_str);
	}
	LOG(log, "};");

	static const uint8_t unpack_test[] = {
		0xD1, 0xD7,
		0x50, 0x8E, 0x42, 0x46, 0x93, 0x11, 0x7F, 0x3E, 0x57, 0x96, 0x32, 0x49, 0x52, 0xF5, 0x15, 0x3F,
		0x51, 0x9A, 0x62, 0xC4, 0x58, 0x45, 0xEB, 0x9E, 0xB6, 0x3B, 0xB2, 0xC7, 0xAA, 0x98, 0xB1, 0x8B,
		0x32, 0x6B, 0xFD, 0x7F, 0x67, 0x5B, 0x24, 0x91, 0xF5, 0xEB, 0xAA, 0x6F, 0xDF, 0x5F, 0x39, 0x8B,
		0x2D, 0x4B, 0x70, 0xDD, 0xF4, 0x5A, 0xBE, 0xFB, 0x40, 0x05, 0xDF, 0x5F, 0x50, 0xD8, 0xD0, 0x7F,
		0x66, 0xA2, 0x81, 0xB0, 0xDA, 0xE0, 0x53, 0xFA, 0xE4, 0x6A, 0xA4, 0x3F, 0x84, 0x29, 0xA7, 0x7A,
		0x81, 0x02, 0xE0, 0xFB, 0x53, 0x91, 0xAA, 0x71, 0xAF, 0xB5, 0x3C, 0xB8, 0xD7, 0xF6, 0xA4, 0x35,
		0xD7, 0x41, 0x79, 0x16, 0x3C, 0xC6, 0x4B, 0x0D, 0xB2, 0xEA, 0xEC, 0xB8, 0xA7, 0xF5, 0x9B, 0x1E,
		0xFD, 0x19, 0xFE, 0x94, 0xA0, 0xDD, 0x4A, 0xA6, 0x22, 0x93, 0xA9, 0xFF, 0xB5, 0x2F, 0x4F, 0x61,
		0xE9, 0x2B, 0x0E, 0x32, 0xB8, 0x17, 0x64, 0x4C, 0xBE, 0xBB, 0xA0, 0x53, 0x70, 0xE5, 0x1D, 0x86,
		0x61, 0xB6, 0x5D, 0x5D, 0x97, 0x3F, 0x5F, 0x0E, 0x9E, 0x35, 0x23, 0x98, 0xAC, 0x78, 0x2C, 0x75,
		0xFD, 0x1A, 0x91, 0xCC, 0x56, 0x07, 0x5D, 0x53, 0x7D, 0x1A, 0x91, 0xCC, 0x56, 0x3E, 0x7E, 0xBE,
		0x58, 0xF9, 0xFB, 0xED, 0x00, 0x17, 0x7B, 0x5D, 0xB3, 0x9D, 0x29, 0xAD, 0x17, 0x18, 0x61, 0x09,
		0x1A, 0x4C, 0x45, 0xFC, 0xF9, 0x5E, 0x58, 0xC9, 0x25, 0x4B, 0xD4, 0x54, 0xB1, 0x62, 0x2C, 0x22,
		0xF5, 0xCF, 0x5B, 0x1D, 0xD9, 0x63, 0xD6, 0xF6, 0x28, 0x60, 0x1F, 0x44, 0xB0, 0xE8, 0x43, 0x12,
		0x7B, 0xFC, 0xC5, 0x83, 0x76, 0x4A, 0x31, 0x6C, 0xD8, 0xB9, 0x10, 0x8F
	};

	size_t total = 0;
	qslice_t s = { (uint8_t*)unpack_test, (uint8_t*)unpack_test + sizeof(unpack_test) };
	while (s.p < s.e) {
		sbuf.p = bigbuf;
		sbuf.e = bigbuf + sizeof(bigbuf);
		hq_header_t h;
		EXPECT_EQ(0, hq_decode_header(&s, &sbuf, NULL, &h));
		char *key = (char*)sbuf.p;
		ssize_t ksz = hq_huffman_decode(&sbuf, h.key, h.key_len);
		EXPECT_GE(ksz, 0);
		char *val = (char*)sbuf.p;
		ssize_t vsz = hq_huffman_decode(&sbuf, h.value, h.value_len);
		EXPECT_GE(vsz, 0);
		LOG(log, "%d %.*s: %.*s", h.static_index, (int)ksz, key, (int)vsz, val);
		total += ksz + 1 + vsz + 2;
	}
	LOG(log, "%d vs %d", (int)total, (int)sizeof(unpack_test));

	static const hq_header_t static_medium = { .static_index = 80 };
	static const hq_header_t static_large = { .static_index = INT_MAX };
	sbuf.p = bigbuf;
	sbuf.e = bigbuf + sizeof(bigbuf);
	EXPECT_EQ(0, hq_encode_header(&sbuf, &HQ_METHOD_GET, NULL, 0, 0));
	EXPECT_EQ(0, hq_encode_header(&sbuf, &static_medium, NULL, 0, 0));
	EXPECT_EQ(0, hq_encode_header(&sbuf, &static_large, NULL, 0, 0));
	EXPECT_EQ(0, hq_encode_header(&sbuf, &HQ_LOCATION, "/index.html", strlen("/index.html"), HQ_PLAINTEXT | HQ_SECURE));

	return finish_test();
}

