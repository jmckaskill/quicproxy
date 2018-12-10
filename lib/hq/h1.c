#include "h1.h"







void http1_init(h1c_connection *c) {
	c->vtable = &http1_connection_vtable;
}

static void close_http1(const hq_tcp_class **vt) {
	h1c_connection *c = (h1c_connection*)vt;
}

const hq_request_class http1_request_vtable = {
	sizeof(h1c_request),
};

const hq_tcp_class http1_connection_vtable = {
	&http1_request_vtable,
	&close_http1,
	&shutdown_http1,
	&received_http1,
};
