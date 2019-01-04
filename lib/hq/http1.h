#pragma once
#include "http.h"
#include "header.h"

typedef struct http1_connection http1_connection;
struct http1_connection {
	const hq_connection_class *vtable;
	const hq_source_class *stream_vtable;
	const hq_source_class **socket;
	hq_continuation notify_socket;
	hq_continuation notify_app;
	http_request *request;
	const char *hostname;
	uint64_t body_remaining;
	bool is_client;
	bool headers_sent;
	bool body_sent;
	bool headers_received;
	bool close_after_request;
	struct {
		size_t len, sent;
		char c_str[4096];
	} txbuf;
	struct {
		size_t len;
		char c_str[4096];
	} rxbuf;
};

const hq_source_class **init_http1_client(http1_connection *c, const char *hostname);
const hq_source_class **init_http1_server(http1_connection *c);
void set_http1_source(http1_connection *c, const hq_source_class **source);




