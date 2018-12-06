#pragma once
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

struct hq_header {
	int index;
	uint16_t key_len, value_len;
	const uint8_t *key, *value;
};

// Header names are stored in huffman encoded form
// The first byte indicates the length.
// Max length is 64 bytes (header + 63 bytes)
#define HDR_MAX_SIZE 64
extern uint8_t HTTP_AUTHORITY[];
extern uint8_t HTTP_METHOD[];
extern uint8_t HTTP_PATH[];
extern uint8_t HTTP_SCHEME[];
extern uint8_t HTTP_STATUS[];
extern uint8_t HTTP_ACCEPT_ENCODING[];
extern uint8_t HTTP_ACCEPT_LANGUAGE[];
extern uint8_t HTTP_ACCEPT_RANGES[];
extern uint8_t HTTP_ACCEPT[];
extern uint8_t HTTP_ACCESS_CONTROL_ALLOW_CREDENTIALS[];
extern uint8_t HTTP_ACCESS_CONTROL_ALLOW_HEADERS[];
extern uint8_t HTTP_ACCESS_CONTROL_ALLOW_METHODS[];
extern uint8_t HTTP_ACCESS_CONTROL_ALLOW_ORIGIN[];
extern uint8_t HTTP_ACCESS_CONTROL_EXPOSE_HEADERS[];
extern uint8_t HTTP_ACCESS_CONTROL_REQUEST_HEADERS[];
extern uint8_t HTTP_ACCESS_CONTROL_REQUEST_METHOD[];
extern uint8_t HTTP_AGE[];
extern uint8_t HTTP_ALT_SVC[];
extern uint8_t HTTP_AUTHORIZATION[];
extern uint8_t HTTP_CACHE_CONTROL[];
extern uint8_t HTTP_CONTENT_DISPOSITION[];
extern uint8_t HTTP_CONTENT_ENCODING[];
extern uint8_t HTTP_CONTENT_LENGTH[];
extern uint8_t HTTP_CONTENT_SECURITY_POLICY[];
extern uint8_t HTTP_CONTENT_TYPE[];
extern uint8_t HTTP_COOKIE[];
extern uint8_t HTTP_DATE[];
extern uint8_t HTTP_EARLY_DATA[];
extern uint8_t HTTP_ETAG[];
extern uint8_t HTTP_EXPECT_CT[];
extern uint8_t HTTP_FORWARDED[];
extern uint8_t HTTP_IF_MODIFIED_SINCE[];
extern uint8_t HTTP_IF_NONE_MATCH[];
extern uint8_t HTTP_IF_RANGE[];
extern uint8_t HTTP_LAST_MODIFIED[];
extern uint8_t HTTP_LINK[];
extern uint8_t HTTP_LOCATION[];
extern uint8_t HTTP_ORIGIN[];
extern uint8_t HTTP_PURPOSE[];
extern uint8_t HTTP_RANGE[];
extern uint8_t HTTP_REFERER[];
extern uint8_t HTTP_SERVER[];
extern uint8_t HTTP_SET_COOKIE[];
extern uint8_t HTTP_STRICT_TRANSPORT_SECURITY[];
extern uint8_t HTTP_TIMING_ALLOW_ORIGIN[];
extern uint8_t HTTP_UPGRADE_INSECURE_REQUESTS[];
extern uint8_t HTTP_USER_AGENT[];
extern uint8_t HTTP_VARY[];
extern uint8_t HTTP_X_CONTENT_TYPE_OPTIONS[];
extern uint8_t HTTP_X_FORWARDED_FOR[];
extern uint8_t HTTP_X_FRAME_OPTIONS[];
extern uint8_t HTTP_X_XSS_PROTECTION[];

int hq_encode_header_name(uint8_t *buf, const char *name);

static inline bool hq_header_name_equals(const uint8_t *a, const uint8_t *b) {
	return a[0] == b[0] && !memcmp(a + 1, b + 1, a[0]);
}

