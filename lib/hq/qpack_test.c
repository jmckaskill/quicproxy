#include "http.h"
#include <cutils/test.h>
#include <cutils/char-array.h>
#include <ctype.h>

static void print_header(log_t *log, uint8_t *buf, const char *name) {
	EXPECT_EQ(0, hq_encode_header_name(buf, name));
	char upper[64], *p = upper;
	for (size_t i = 0; name[i]; i++) {
		char ch = name[i];
		if (ch == '-') {
			*p++ = '_';
		} else if (ch == ':') {
			continue;
		} else {
			*p++ = ch - 'a' + 'A';
		}
	}
	*p = 0;
	struct {
		size_t len;
		char c_str[128];
	} data;
	data.len = 0;
	for (size_t i = 0; i <= buf[0]; i++) {
		ca_addf(&data, "%c %d", i ? ',' : '{', buf[i]);
	}
	//LOG(log, "uint8_t HTTP_%s[] = %s};", upper, data.c_str);
	LOG(log, "extern uint8_t HTTP_%s[];", upper);
}

int main(int argc, const char *argv[]) {
	log_t *log = start_test(argc, argv);

	uint8_t buf[HDR_MAX_SIZE];
	EXPECT_EQ(0, hq_encode_header_name(buf, "custom-key"));
	uint8_t custom_key[] = { 8, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f };
	EXPECT_BYTES_EQ(custom_key, custom_key[0] + 1, buf, buf[0] + 1);

	print_header(log, buf, ":authority");
	print_header(log, buf, ":method");
	print_header(log, buf, ":path");
	print_header(log, buf, ":scheme");
	print_header(log, buf, ":status");
	print_header(log, buf, "accept-encoding");
	print_header(log, buf, "accept-language");
	print_header(log, buf, "accept-ranges");
	print_header(log, buf, "accept");
	print_header(log, buf, "access-control-allow-credentials");
	print_header(log, buf, "access-control-allow-headers");
	print_header(log, buf, "access-control-allow-methods");
	print_header(log, buf, "access-control-allow-origin");
	print_header(log, buf, "access-control-expose-headers");
	print_header(log, buf, "access-control-request-headers");
	print_header(log, buf, "access-control-request-method");
	print_header(log, buf, "age");
	print_header(log, buf, "alt-svc");
	print_header(log, buf, "authorization");
	print_header(log, buf, "cache-control");
	print_header(log, buf, "content-disposition");
	print_header(log, buf, "content-encoding");
	print_header(log, buf, "content-length");
	print_header(log, buf, "content-security-policy");
	print_header(log, buf, "content-type");
	print_header(log, buf, "cookie");
	print_header(log, buf, "date");
	print_header(log, buf, "early-data");
	print_header(log, buf, "etag");
	print_header(log, buf, "expect-ct");
	print_header(log, buf, "forwarded");
	print_header(log, buf, "if-modified-since");
	print_header(log, buf, "if-none-match");
	print_header(log, buf, "if-range");
	print_header(log, buf, "last-modified");
	print_header(log, buf, "link");
	print_header(log, buf, "location");
	print_header(log, buf, "origin");
	print_header(log, buf, "purpose");
	print_header(log, buf, "range");
	print_header(log, buf, "referer");
	print_header(log, buf, "server");
	print_header(log, buf, "set-cookie");
	print_header(log, buf, "strict-transport-security");
	print_header(log, buf, "timing-allow-origin");
	print_header(log, buf, "upgrade-insecure-requests");
	print_header(log, buf, "user-agent");
	print_header(log, buf, "vary");
	print_header(log, buf, "x-content-type-options");
	print_header(log, buf, "x-forwarded-for");
	print_header(log, buf, "x-frame-options");
	print_header(log, buf, "x-xss-protection");

	return finish_test();
}

