#include "header.h"
#include <cutils/test.h>
#include <cutils/str.h>
#include <cutils/hash.h>
#include <cutils/vector.h>
#include <ctype.h>
#include <limits.h>

struct csym {
	unsigned off;
	unsigned sz;
	uint8_t hash;
	str_t c;
};

static void print_huffman(log_t *log, const char *value, struct csym *sym) {
	static unsigned offset;
	uint8_t buf[128];
	ssize_t sz = hq_encode_value(buf, sizeof(buf), value, strlen(value));
	EXPECT_GE(sz, 0);
	if (!strcmp(value, "")) {
		sym->c = str_init("");
	} else if (!strcmp(value, "/")) {
		sym->c = str_init("_SLASH");
	} else if (!strcmp(value, "*/*")) {
		sym->c = str_init("_STAR_STAR");
	} else {
		sym->c = str_init("_");
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
	if (sz) {
		str_t data = STR_INIT;
		for (ssize_t i = 0; i < sz; i++) {
			str_addf(&data, "%d,%s", buf[i], (i && !(i & 15) && (i + 1) < sz) ? "\n\t" : " ");
		}
		LOG(log, "\t%s // %s", data.c_str, value);
		str_destroy(&data);
	}
	sym->off = offset;
	sym->sz = (unsigned)sz;
	sym->hash = hq_compute_hash(buf, sz);
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
	struct header *h = APPEND_ZERO(&headers);
	h->index = index;

	bool added;
	size_t idx = INSERT_BLOB_HASH(&symbols, key, strlen(key), &added);
	if (added) {
		print_huffman(log, key, &symbols.values[idx]);
	}
	h->key = key;

	idx = INSERT_BLOB_HASH(&symbols, value, strlen(value), &added);
	if (added) {
		print_huffman(log, value, &symbols.values[idx]);
	}
	h->value = value;
	rawlen += strlen(key) + strlen(value);
}

static void print_dictionary(log_t *log) {
	LOG(log, "static const hq_dict_entry_t entries[] = {");
	size_t next_index = 0;
	for (size_t i = 0; i < headers.size; i++) {
		struct header *h = &headers.v[i];
		if (h->index == next_index) {
			struct csym *k = &symbols.values[FIND_BLOB_HASH(&symbols, h->key, strlen(h->key))];
			struct csym *v = h->value ? &symbols.values[FIND_BLOB_HASH(&symbols, h->value, strlen(h->value))] : NULL;
			LOG(log, "\t{ %u, %u, %u, %u },", k->off, k->sz, v ? v->off : 0, v ? v->sz : 0);
			next_index++;
		}
	}
	LOG(log, "};");
	LOG(log, "");
}

static void print_headers(log_t *log, bool declare) {
	for (size_t i = 0; i < headers.size; i++) {
		struct header *h = &headers.v[i];
		struct csym *k = &symbols.values[FIND_BLOB_HASH(&symbols, h->key, strlen(h->key))];
		struct csym *v = h->value ? &symbols.values[FIND_BLOB_HASH(&symbols, h->value, strlen(h->value))] : NULL;

		if (declare) {
			LOG(log, "extern const hq_header HQ%s%s;", k->c.c_str, v ? v->c.c_str : "");
		} else {
			LOG(log, "const hq_header HQ%s%s = { HUF+%u, HUF+%u, HQ_HEADER_COMPRESSED, %u, %u, %u, 0 };", k->c.c_str, v->c.c_str, k->off, v->off, v->sz, k->sz, k->hash);
		}
	}
}

struct node {
	struct node *child[2];
	char value;
};

static uint16_t write_node(uint8_t *p, uint16_t off, const struct node *n, unsigned bitsz) {
	assert(off < UINT16_MAX);
	if (!n) {
		p[off] = 0;
		return off + 1;
	} else if (n->value) {
		p[off] = n->value;
		return off + 1;
	} else {
		uint16_t right = write_node(p, off + 1, n->child[0], bitsz);
		p[off] = (uint8_t)(0 - (right - off - 1));
		return write_node(p, right, n->child[1], bitsz);
	}
}

static void add_node(struct node *root, struct node **pnext, uint32_t encoder, char ch) {
	uint32_t bits = encoder >> 24;
	uint32_t value = encoder & 0xFFFFFF;
	struct node *p = root;
	while (bits) {
		int bit = (value >> (--bits)) & 1;
		struct node **c = &p->child[bit];
		if (!*c) {
			assert(*pnext < root + 1024);
			*c = (*pnext)++;
		}
		p = *c;
		assert(!p->value);
	}
	p->value = ch;
}

static void print_decoder(log_t *log, const char *name, int8_t *buf, size_t sz) {
	LOG(log, "");
	LOG(log, "static const int8_t %s[] = {", name);
	for (size_t i = 0; i < sz; i += 8) {
		struct {
			size_t len;
			char c_str[256];
		} s;
		s.len = 0;
		for (size_t j = i; j < i + 8 && j < sz; j++) {
			ca_addf(&s, "%c", (j & 7) ? ' ' : '\t');
			if (buf[j] <= 0) {
				ca_addf(&s, "%d,", buf[j]);
			} else if (buf[j] == '\'' || buf[j] == '\\') {
				ca_addf(&s, "'\\%c',", buf[j]);
			} else {
				ca_addf(&s, "'%c',", buf[j]);
			}
		}
		LOG(log, "%s", s.c_str);
	}
	LOG(log, "};");
}

static size_t generate_value_decoder(int8_t *buf) {
	struct node nodes[1024], *next = nodes;
	struct node *root = next++;
	memset(nodes, 0, sizeof(nodes));
	for (size_t i = 0; hq_hdr_encoder[i]; i++) {
		add_node(root, &next, hq_hdr_encoder[i], (char)(i + ' '));
	}
	// add a dummy node for the padding to play out
	add_node(root, &next, 0xFF | (8 << 24), 0);
	return write_node((uint8_t*)buf, 0, root, 8);
}

static size_t generate_key_decoder(int8_t *buf) {
	struct node nodes[1024], *next = nodes;
	struct node *root = next++;
	memset(nodes, 0, sizeof(nodes));
	for (size_t i = 0; hq_hdr_encoder[i]; i++) {
		char ch = (char)(i + ' ');
		if (('0' <= ch && ch <= '9') || ('a' <= ch && ch <= 'z') || ch == ':' || ch == '-') {
			add_node(root, &next, hq_hdr_encoder[i], ch);
		}
	}
	// add a dummy node for the padding to play out
	add_node(root, &next, 0xFF | (8 << 24), 0);
	return write_node((uint8_t*)buf, 0, root, 8);
}

int main(int argc, const char *argv[]) {
	log_t *log = start_test(argc, argv);

	int8_t ibuf[256];
	size_t sz = generate_value_decoder(ibuf);
	print_decoder(log, "huf_decode_value", ibuf, sz);

	sz = generate_key_decoder(ibuf);
	print_decoder(log, "huf_decode_key", ibuf, sz);

	uint8_t buf[4096];
	uint8_t custom_key[] = { 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f };
	EXPECT_EQ(sizeof(custom_key), hq_encode_http1_key(buf, sizeof(buf), "Custom-Key", strlen("custom-key")));
	EXPECT_BYTES_EQ(custom_key, sizeof(custom_key), buf, sizeof(custom_key));

	EXPECT_EQ(0, hq_verify_http2_key(custom_key, sizeof(custom_key)));
	EXPECT_EQ(-1, hq_verify_http2_key(custom_key, sizeof(custom_key) - 1));

	LOG(log, "static const uint8_t HUF[] = {");
	insert_header(log, 0, ":authority", "");
	insert_header(log, 1, ":path", "");
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
	insert_header(log, 15, ":method", "");
	insert_header(log, 15, ":method", "CONNECT");
	insert_header(log, 16, ":method", "DELETE");
	insert_header(log, 17, ":method", "GET");
	insert_header(log, 18, ":method", "HEAD");
	insert_header(log, 19, ":method", "OPTIONS");
	insert_header(log, 20, ":method", "POST");
	insert_header(log, 21, ":method", "PUT");
	insert_header(log, 22, ":scheme", "http");
	insert_header(log, 23, ":scheme", "https");
	insert_header(log, 24, ":status", "");
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
	print_headers(log, false);
	LOG(log, "");
	print_headers(log, true);
	LOG(log, "");
	print_dictionary(log);
	LOG(log, "");
	LOG(log, "extern const hq_dictionary_t HQ_STATIC_DICT;");

#if 0
	hq_header_table t = { 0 };
	EXPECT_EQ(0, hq_hdr_set(&t, &HQ_CACHE_CONTROL_MAX_AGE_0, NULL, 0, 0));
	EXPECT_EQ(0, hq_hdr_add(&t, &HQ_CACHE_CONTROL_NO_CACHE, NULL, 0, 0));
	EXPECT_EQ(0, hq_hdr_set(&t, &HQ_CONTENT_TYPE_IMAGE_GIF, NULL, 0, 0));
	EXPECT_EQ(0, hq_hdr_set(&t, &HQ_CONTENT_TYPE_APPLICATION_DNS_MESSAGE, "test", 4, 0));
	EXPECT_EQ(0, hq_hdr_set(&t, &HQ_AUTHORITY, "www.google.com", strlen("www.google.com"), 0));
	EXPECT_EQ(0, hq_hdr_set(&t, &HQ_IF_NONE_MATCH, NULL, 0, 0));
	EXPECT_EQ(0, hq_hdr_set(&t, &HQ_CONTENT_LENGTH_0, NULL, 0, 0));
	EXPECT_PTREQ(NULL, hq_hdr_get(&t, &HQ_STATUS_200));
	const hq_header *n = hq_hdr_get(&t, &HQ_CONTENT_TYPE_TEXT_PLAIN);
	EXPECT_TRUE(n != NULL);
	EXPECT_STREQ(n->value, "test");
	hq_header h = { 0 };
	strcpy((char*)buf, "Content-Type");
	h.key_len = (uint8_t)hq_encode_key(buf, sizeof(buf), (char*)buf, strlen("Content-Type"));
	h.key = buf;
	h.hash = hq_compute_hash(h.key, h.key_len);
	n = hq_hdr_get(&t, &h);
	EXPECT_TRUE(n != NULL);
	EXPECT_STREQ(n->value, "test");
#endif

	return finish_test();
}

