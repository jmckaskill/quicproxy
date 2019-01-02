#include "http.h"

static int start_read_request(const hq_stream_class **vt, const hq_stream_class **sink, int minsz, const void **pdata) {
	http_request *r = container_of(vt, http_request, vtable);
	r->sink = sink;
	if (r->finished) {
		return 0;
	} else if (!r->connection) {
		return HQ_PENDING;
	} else {
		return (*r->connection)->start_read_request(r->connection, r, minsz, pdata);
	}
}

static void finish_read_request(const hq_stream_class **vt, int sz) {
	http_request *r = container_of(vt, http_request, vtable);
	r->sink = NULL;
	if (r->connection) {
		(*r->connection)->finish_read_request(r->connection, r, sz);
	}
}

static void request_read_finished(const hq_stream_class **vt, const hq_stream_class **source, int close) {
	http_request *r = container_of(vt, http_request, vtable);
	r->source = source;
	if (r->connection) {
		(*r->connection)->request_ready(r->connection, r, close);
	}
}

static const hq_stream_class http_request_vtable = {
	&start_read_request,
	&finish_read_request,
	&request_read_finished,
};

void init_http_request(http_request *r) {
	memset(r, 0, sizeof(*r));
	r->vtable = &http_request_vtable;
}

void http_request_ready(http_request *r, int error) {
	const hq_stream_class **sink = r->sink;
	if (sink) {
		r->sink = NULL;
		(*sink)->read_finished(sink, &r->vtable, error);
	}
}
