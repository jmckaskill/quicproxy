#pragma once
#include "http.h"
#include "header.h"

typedef struct http1_request http1_request;
struct http1_request {
	const hq_stream_class *vtable;
	const hq_stream_class **source;
	const hq_stream_class **sink;
	http1_connection *c;
	http1_request *next;
	hq_header_table hdrs;
	size_t hdr_used, remaining;
	struct {
		char c_str[4096];
		size_t len;
	} hdr;
};

hq_header_table *init_http1_request(http1_request *r);

typedef struct http1_connection http1_connection;
struct http1_connection {
	const hq_connection_class *vtable;
	const hq_stream_class *stream_vtable;
	const hq_callback_class **cb;
	const hq_stream_class **socket;
	http1_request *request;
	http1_request *last;
	const char *hostname;
	bool should_close;
};

void init_http1_connection(http1_connection *c, const hq_callback_class **cb, const char *hostname, const hq_stream_class **socket);
