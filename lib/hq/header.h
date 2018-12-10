#pragma once
#include "lib/quic/common.h"

#define HQ_HEADER_TABLE_SIZE 32
#define HQ_MAX_HEADERS UINT8_C(128)
#define HQ_MAX_HEADER_SIZE 4096

#define HQ_HEADER_COMPRESSED 0x4000
#define HQ_HEADER_SECURE 0x8000
#define HQ_HEADER_VALUE_SHIFT 2

typedef struct hq_header hq_header;
struct hq_header {
	const void *key, *value;
	uint32_t hash;
	uint16_t value_len : 14;
	uint16_t compressed : 1;
	uint16_t secure : 1;
	uint8_t key_len;
	int8_t next;
};

typedef struct hq_header_table hq_header_table;
struct hq_header_table {
	const br_hash_class *digest;
	int8_t table[HQ_HEADER_TABLE_SIZE];
	hq_header headers[HQ_MAX_HEADERS];
	uint32_t used[HQ_MAX_HEADERS / 32];
};

void hq_hdr_init(hq_header_table *t);
int hq_hdr_set(hq_header_table *t, const hq_header *h, const void *value, size_t len, int flags);
int hq_hdr_remove(hq_header_table *t, const hq_header *h);

const hq_header *hq_hdr_get(hq_header_table *t, const hq_header *h);
const hq_header *hq_hdr_next(hq_header_table *t, const hq_header *h);

extern const uint32_t hq_hdr_encoder[];
ssize_t hq_encode_value(void *buf, size_t bufsz, const char *data, size_t len);
ssize_t hq_encode_key(void *buf, size_t bufsz, const char *data, size_t len);
ssize_t hq_decode_value(void *buf, size_t bufsz, const uint8_t *data, size_t len);
int hq_verify_key(const uint8_t *data, size_t len);

uint32_t hq_compute_hash(const uint8_t *key, size_t len);

extern const hq_header HQ_AUTHORITY;
extern const hq_header HQ_PATH_SLASH;
extern const hq_header HQ_AGE_0;
extern const hq_header HQ_CONTENT_DISPOSITION;
extern const hq_header HQ_CONTENT_LENGTH_0;
extern const hq_header HQ_COOKIE;
extern const hq_header HQ_DATE;
extern const hq_header HQ_ETAG;
extern const hq_header HQ_IF_MODIFIED_SINCE;
extern const hq_header HQ_IF_NONE_MATCH;
extern const hq_header HQ_LAST_MODIFIED;
extern const hq_header HQ_LINK;
extern const hq_header HQ_LOCATION;
extern const hq_header HQ_REFERER;
extern const hq_header HQ_SET_COOKIE;
extern const hq_header HQ_METHOD_CONNECT;
extern const hq_header HQ_METHOD_DELETE;
extern const hq_header HQ_METHOD_GET;
extern const hq_header HQ_METHOD_HEAD;
extern const hq_header HQ_METHOD_OPTIONS;
extern const hq_header HQ_METHOD_POST;
extern const hq_header HQ_METHOD_PUT;
extern const hq_header HQ_SCHEME_HTTP;
extern const hq_header HQ_SCHEME_HTTPS;
extern const hq_header HQ_STATUS_103;
extern const hq_header HQ_STATUS_200;
extern const hq_header HQ_STATUS_304;
extern const hq_header HQ_STATUS_404;
extern const hq_header HQ_STATUS_503;
extern const hq_header HQ_ACCEPT_STAR_STAR;
extern const hq_header HQ_ACCEPT_APPLICATION_DNS_MESSAGE;
extern const hq_header HQ_ACCEPT_ENCODING_GZIP_DEFLATE_BR;
extern const hq_header HQ_ACCEPT_RANGES_BYTES;
extern const hq_header HQ_ACCESS_CONTROL_ALLOW_HEADERS_CACHE_CONTROL;
extern const hq_header HQ_ACCESS_CONTROL_ALLOW_HEADERS_CONTENT_TYPE;
extern const hq_header HQ_ACCESS_CONTROL_ALLOW_ORIGIN_STAR;
extern const hq_header HQ_CACHE_CONTROL_MAX_AGE_0;
extern const hq_header HQ_CACHE_CONTROL_MAX_AGE_2592000;
extern const hq_header HQ_CACHE_CONTROL_MAX_AGE_604800;
extern const hq_header HQ_CACHE_CONTROL_NO_CACHE;
extern const hq_header HQ_CACHE_CONTROL_NO_STORE;
extern const hq_header HQ_CACHE_CONTROL_PUBLIC_MAX_AGE_31536000;
extern const hq_header HQ_CONTENT_ENCODING_BR;
extern const hq_header HQ_CONTENT_ENCODING_GZIP;
extern const hq_header HQ_CONTENT_TYPE_APPLICATION_DNS_MESSAGE;
extern const hq_header HQ_CONTENT_TYPE_APPLICATION_JAVASCRIPT;
extern const hq_header HQ_CONTENT_TYPE_APPLICATION_JSON;
extern const hq_header HQ_CONTENT_TYPE_APPLICATION_X_WWW_FORM_URLENCODED;
extern const hq_header HQ_CONTENT_TYPE_IMAGE_GIF;
extern const hq_header HQ_CONTENT_TYPE_IMAGE_JPEG;
extern const hq_header HQ_CONTENT_TYPE_IMAGE_PNG;
extern const hq_header HQ_CONTENT_TYPE_TEXT_CSS;
extern const hq_header HQ_CONTENT_TYPE_TEXT_HTML_CHARSET_UTF_8;
extern const hq_header HQ_CONTENT_TYPE_TEXT_PLAIN;
extern const hq_header HQ_CONTENT_TYPE_TEXT_PLAIN_CHARSET_UTF_8;
extern const hq_header HQ_RANGE_BYTES_0_;
extern const hq_header HQ_STRICT_TRANSPORT_SECURITY_MAX_AGE_31536000;
extern const hq_header HQ_STRICT_TRANSPORT_SECURITY_MAX_AGE_31536000_INCLUDESUBDOMAINS;
extern const hq_header HQ_STRICT_TRANSPORT_SECURITY_MAX_AGE_31536000_INCLUDESUBDOMAINS_PRELOAD;
extern const hq_header HQ_VARY_ACCEPT_ENCODING;
extern const hq_header HQ_VARY_ORIGIN;
extern const hq_header HQ_X_CONTENT_TYPE_OPTIONS_NOSNIFF;
extern const hq_header HQ_X_XSS_PROTECTION_1_MODE_BLOCK;
extern const hq_header HQ_STATUS_100;
extern const hq_header HQ_STATUS_204;
extern const hq_header HQ_STATUS_206;
extern const hq_header HQ_STATUS_302;
extern const hq_header HQ_STATUS_400;
extern const hq_header HQ_STATUS_403;
extern const hq_header HQ_STATUS_421;
extern const hq_header HQ_STATUS_425;
extern const hq_header HQ_STATUS_500;
extern const hq_header HQ_ACCEPT_LANGUAGE;
extern const hq_header HQ_ACCESS_CONTROL_ALLOW_CREDENTIALS_FALSE;
extern const hq_header HQ_ACCESS_CONTROL_ALLOW_CREDENTIALS_TRUE;
extern const hq_header HQ_ACCESS_CONTROL_ALLOW_HEADERS_STAR;
extern const hq_header HQ_ACCESS_CONTROL_ALLOW_METHODS_GET;
extern const hq_header HQ_ACCESS_CONTROL_ALLOW_METHODS_GET_POST_OPTIONS;
extern const hq_header HQ_ACCESS_CONTROL_ALLOW_METHODS_OPTIONS;
extern const hq_header HQ_ACCESS_CONTROL_EXPOSE_HEADERS_CONTENT_LENGTH;
extern const hq_header HQ_ACCESS_CONTROL_REQUEST_HEADERS_CONTENT_TYPE;
extern const hq_header HQ_ACCESS_CONTROL_REQUEST_METHOD_GET;
extern const hq_header HQ_ACCESS_CONTROL_REQUEST_METHOD_POST;
extern const hq_header HQ_ALT_SVC_CLEAR;
extern const hq_header HQ_AUTHORIZATION;
extern const hq_header HQ_CONTENT_SECURITY_POLICY_SCRIPT_SRC_NONE_OBJECT_SRC_NONE_BASE_URI_NONE;
extern const hq_header HQ_EARLY_DATA_1;
extern const hq_header HQ_EXPECT_CT;
extern const hq_header HQ_FORWARDED;
extern const hq_header HQ_IF_RANGE;
extern const hq_header HQ_ORIGIN;
extern const hq_header HQ_PURPOSE_PREFETCH;
extern const hq_header HQ_SERVER;
extern const hq_header HQ_TIMING_ALLOW_ORIGIN_STAR;
extern const hq_header HQ_UPGRADE_INSECURE_REQUESTS_1;
extern const hq_header HQ_USER_AGENT;
extern const hq_header HQ_X_FORWARDED_FOR;
extern const hq_header HQ_X_FRAME_OPTIONS_DENY;
extern const hq_header HQ_X_FRAME_OPTIONS_SAMEORIGIN;

