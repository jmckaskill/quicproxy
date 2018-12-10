#pragma once
#include "http.h"

typedef struct h1c_request h1c_request;
struct h1c_request {
	const hq_stream_class *vtable;
};

typedef struct h1c_connection h1c_connection;
struct h1c_connection {
	const hq_tcp_class *vtable;
	const hq_callback_class **cb;

};

extern const hq_tcp_class http1_connection_vtable;
void http1_init(h1c_connection *c);

typedef struct https1_connection https1_connection;
struct https1_connection {
	h1c_connection h;
};