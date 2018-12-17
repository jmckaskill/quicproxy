#pragma once
#include "http.h"
#include "header.h"

struct http1_hdrbuf {
	size_t used, len;
	char c_str[4096];
};

typedef struct http1_connection http1_connection;
struct http1_connection {
	const hq_connection_class *vtable;
	const hq_stream_class *stream_vtable;
	const hq_callback_class **cb;
	const hq_stream_class **socket;
	http_request *request;
	http_request *last;
	const char *hostname;
	uint32_t flags;
	size_t body_to_send;
	size_t body_to_recv;
	struct http1_hdrbuf hsend, hrecv;
};

void start_http1_client(http1_connection *c, const hq_callback_class **cb, const char *hostname, const hq_stream_class **socket);
