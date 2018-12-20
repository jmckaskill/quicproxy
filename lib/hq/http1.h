#pragma once
#include "http.h"
#include "header.h"

typedef struct http1_connection http1_connection;
struct http1_connection {
	const hq_connection_class *vtable;
	const hq_stream_class *stream_vtable;
	const hq_callback_class **cb;
	const hq_stream_class **socket;
	http_request *request;
	const char *hostname;
	uint64_t brecv;
	bool is_client;
	bool send_finished;
	bool recv_finished;
	bool close_after_request;
	bool recv_ignore;
	struct {
		size_t len, sent;
		char c_str[4096];
	} txbuf;
	struct {
		size_t len;
		char c_str[4096];
	} rxbuf;
};

void start_http1_client(http1_connection *c, const hq_callback_class **cb, const char *hostname, const hq_stream_class **socket);
