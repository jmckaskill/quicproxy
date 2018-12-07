#pragma once
#include "lib/quic/common.h"

typedef struct hq_header hq_header_t;
struct hq_header {
	int static_index;
	uint16_t key_len;
	uint16_t value_len;
	bool secure;
	const uint8_t *key, *value;
};

typedef struct hq_dict_entry hq_dict_entry_t;
struct hq_dict_entry {
	uint16_t name_off;
	uint16_t name_len;
	uint16_t value_off;
	uint16_t value_len;
};

typedef struct hq_dictionary hq_dictionary_t;
struct hq_dictionary {
	const uint8_t *data;
	const hq_dict_entry_t *entries;
	size_t num_entries;
	int64_t discarded;
	int64_t base;
	int64_t max;
};

// Header names are stored in huffman encoded form
// The first byte indicates the length.
// Max length is 64 bytes (header + 63 bytes)
#define HDR_MAX_SIZE 64

ssize_t hq_huffman_encode(qslice_t *s, const char *data, size_t len);
ssize_t hq_huffman_decode(qslice_t *s, const uint8_t *data, size_t len);
size_t hq_generate_decoder(int8_t *p);

static inline bool hq_header_name_equals(const uint8_t *a, const uint8_t *b) {
	return a[0] == b[0] && !memcmp(a + 1, b + 1, a[0]);
}

int hq_decode_header(qslice_t *s, qslice_t *buf, const hq_dictionary_t *dict, hq_header_t *hdr);

#define HQ_SECURE 1
#define HQ_PLAINTEXT 2
int hq_encode_header(qslice_t *s, const hq_header_t *hdr, const void *value, size_t len, int flags);

extern const hq_dictionary_t HQ_STATIC_DICT;

extern const hq_header_t HQ_AUTHORITY;
extern const hq_header_t HQ_PATH_SLASH;
extern const hq_header_t HQ_AGE_0;
extern const hq_header_t HQ_CONTENT_DISPOSITION;
extern const hq_header_t HQ_CONTENT_LENGTH_0;
extern const hq_header_t HQ_COOKIE;
extern const hq_header_t HQ_DATE;
extern const hq_header_t HQ_ETAG;
extern const hq_header_t HQ_IF_MODIFIED_SINCE;
extern const hq_header_t HQ_IF_NONE_MATCH;
extern const hq_header_t HQ_LAST_MODIFIED;
extern const hq_header_t HQ_LINK;
extern const hq_header_t HQ_LOCATION;
extern const hq_header_t HQ_REFERER;
extern const hq_header_t HQ_SET_COOKIE;
extern const hq_header_t HQ_METHOD_CONNECT;
extern const hq_header_t HQ_METHOD_DELETE;
extern const hq_header_t HQ_METHOD_GET;
extern const hq_header_t HQ_METHOD_HEAD;
extern const hq_header_t HQ_METHOD_OPTIONS;
extern const hq_header_t HQ_METHOD_POST;
extern const hq_header_t HQ_METHOD_PUT;
extern const hq_header_t HQ_SCHEME_HTTP;
extern const hq_header_t HQ_SCHEME_HTTPS;
extern const hq_header_t HQ_STATUS_103;
extern const hq_header_t HQ_STATUS_200;
extern const hq_header_t HQ_STATUS_304;
extern const hq_header_t HQ_STATUS_404;
extern const hq_header_t HQ_STATUS_503;
extern const hq_header_t HQ_ACCEPT_STAR_STAR;
extern const hq_header_t HQ_ACCEPT_APPLICATION_DNS_MESSAGE;
extern const hq_header_t HQ_ACCEPT_ENCODING_GZIP_DEFLATE_BR;
extern const hq_header_t HQ_ACCEPT_RANGES_BYTES;
extern const hq_header_t HQ_ACCESS_CONTROL_ALLOW_HEADERS_CACHE_CONTROL;
extern const hq_header_t HQ_ACCESS_CONTROL_ALLOW_HEADERS_CONTENT_TYPE;
extern const hq_header_t HQ_ACCESS_CONTROL_ALLOW_ORIGIN_STAR;
extern const hq_header_t HQ_CACHE_CONTROL_MAX_AGE_0;
extern const hq_header_t HQ_CACHE_CONTROL_MAX_AGE_2592000;
extern const hq_header_t HQ_CACHE_CONTROL_MAX_AGE_604800;
extern const hq_header_t HQ_CACHE_CONTROL_NO_CACHE;
extern const hq_header_t HQ_CACHE_CONTROL_NO_STORE;
extern const hq_header_t HQ_CACHE_CONTROL_PUBLIC_MAX_AGE_31536000;
extern const hq_header_t HQ_CONTENT_ENCODING_BR;
extern const hq_header_t HQ_CONTENT_ENCODING_GZIP;
extern const hq_header_t HQ_CONTENT_TYPE_APPLICATION_DNS_MESSAGE;
extern const hq_header_t HQ_CONTENT_TYPE_APPLICATION_JAVASCRIPT;
extern const hq_header_t HQ_CONTENT_TYPE_APPLICATION_JSON;
extern const hq_header_t HQ_CONTENT_TYPE_APPLICATION_X_WWW_FORM_URLENCODED;
extern const hq_header_t HQ_CONTENT_TYPE_IMAGE_GIF;
extern const hq_header_t HQ_CONTENT_TYPE_IMAGE_JPEG;
extern const hq_header_t HQ_CONTENT_TYPE_IMAGE_PNG;
extern const hq_header_t HQ_CONTENT_TYPE_TEXT_CSS;
extern const hq_header_t HQ_CONTENT_TYPE_TEXT_HTML_CHARSET_UTF_8;
extern const hq_header_t HQ_CONTENT_TYPE_TEXT_PLAIN;
extern const hq_header_t HQ_CONTENT_TYPE_TEXT_PLAIN_CHARSET_UTF_8;
extern const hq_header_t HQ_RANGE_BYTES_0_;
extern const hq_header_t HQ_STRICT_TRANSPORT_SECURITY_MAX_AGE_31536000;
extern const hq_header_t HQ_STRICT_TRANSPORT_SECURITY_MAX_AGE_31536000_INCLUDESUBDOMAINS;
extern const hq_header_t HQ_STRICT_TRANSPORT_SECURITY_MAX_AGE_31536000_INCLUDESUBDOMAINS_PRELOAD;
extern const hq_header_t HQ_VARY_ACCEPT_ENCODING;
extern const hq_header_t HQ_VARY_ORIGIN;
extern const hq_header_t HQ_X_CONTENT_TYPE_OPTIONS_NOSNIFF;
extern const hq_header_t HQ_X_XSS_PROTECTION_1_MODE_BLOCK;
extern const hq_header_t HQ_STATUS_100;
extern const hq_header_t HQ_STATUS_204;
extern const hq_header_t HQ_STATUS_206;
extern const hq_header_t HQ_STATUS_302;
extern const hq_header_t HQ_STATUS_400;
extern const hq_header_t HQ_STATUS_403;
extern const hq_header_t HQ_STATUS_421;
extern const hq_header_t HQ_STATUS_425;
extern const hq_header_t HQ_STATUS_500;
extern const hq_header_t HQ_ACCEPT_LANGUAGE;
extern const hq_header_t HQ_ACCESS_CONTROL_ALLOW_CREDENTIALS_FALSE;
extern const hq_header_t HQ_ACCESS_CONTROL_ALLOW_CREDENTIALS_TRUE;
extern const hq_header_t HQ_ACCESS_CONTROL_ALLOW_HEADERS_STAR;
extern const hq_header_t HQ_ACCESS_CONTROL_ALLOW_METHODS_GET;
extern const hq_header_t HQ_ACCESS_CONTROL_ALLOW_METHODS_GET_POST_OPTIONS;
extern const hq_header_t HQ_ACCESS_CONTROL_ALLOW_METHODS_OPTIONS;
extern const hq_header_t HQ_ACCESS_CONTROL_EXPOSE_HEADERS_CONTENT_LENGTH;
extern const hq_header_t HQ_ACCESS_CONTROL_REQUEST_HEADERS_CONTENT_TYPE;
extern const hq_header_t HQ_ACCESS_CONTROL_REQUEST_METHOD_GET;
extern const hq_header_t HQ_ACCESS_CONTROL_REQUEST_METHOD_POST;
extern const hq_header_t HQ_ALT_SVC_CLEAR;
extern const hq_header_t HQ_AUTHORIZATION;
extern const hq_header_t HQ_CONTENT_SECURITY_POLICY_SCRIPT_SRC_NONE_OBJECT_SRC_NONE_BASE_URI_NONE;
extern const hq_header_t HQ_EARLY_DATA_1;
extern const hq_header_t HQ_EXPECT_CT;
extern const hq_header_t HQ_FORWARDED;
extern const hq_header_t HQ_IF_RANGE;
extern const hq_header_t HQ_ORIGIN;
extern const hq_header_t HQ_PURPOSE_PREFETCH;
extern const hq_header_t HQ_SERVER;
extern const hq_header_t HQ_TIMING_ALLOW_ORIGIN_STAR;
extern const hq_header_t HQ_UPGRADE_INSECURE_REQUESTS_1;
extern const hq_header_t HQ_USER_AGENT;
extern const hq_header_t HQ_X_FORWARDED_FOR;
extern const hq_header_t HQ_X_FRAME_OPTIONS_DENY;
extern const hq_header_t HQ_X_FRAME_OPTIONS_SAMEORIGIN;

