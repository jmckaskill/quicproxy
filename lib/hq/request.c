#include "http.h"

static ssize_t read_request(const hq_stream_class **vt, const hq_stream_class **sink, size_t off, const void **pdata) {
	http_request *r = container_of(vt, http_request, vtable);
	r->sink = sink;
	return r->connection ? (*r->connection)->read_request(r->connection, r, off, pdata) : HQ_PENDING;
}

static void finish_read_request(const hq_stream_class **vt, ssize_t sz) {
	http_request *r = container_of(vt, http_request, vtable);
	r->sink = NULL;
	if (r->connection) {
		(*r->connection)->finish_read_request(r->connection, r, sz);
	}
}

static void request_ready(const hq_stream_class **vt, const hq_stream_class **source, int close) {
	http_request *r = container_of(vt, http_request, vtable);
	r->source = source;
	if (r->connection) {
		(*r->connection)->request_ready(r->connection, r, close);
	}
}

static const hq_stream_class http_request_vtable = {
	&read_request,
	&finish_read_request,
	&request_ready,
};

void init_http_request(http_request *r) {
	memset(r, 0, sizeof(*r));
	r->vtable = &http_request_vtable;
}

