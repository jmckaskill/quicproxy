#include "http.h"

static void close_read_request(const hq_source_class **vt, int error) {
	http_request *r = container_of(vt, http_request, vtable);
	assert(!r->notify);
	// TODO ... now what?
}

static ssize_t start_read_request(const hq_source_class **vt, size_t off, size_t minsz, const void **pdata, hq_notify_fn notify, void *user) {
	http_request *r = container_of(vt, http_request, vtable);
	r->notify = notify;
	r->notify_user = user;
	if (r->finished) {
		return 0;
	} else if (!r->connection) {
		return HQ_PENDING;
	} else {
		return (*r->connection)->start_read_request(r->connection, r, off, minsz, pdata);
	}
}

static void finish_read_request(const hq_source_class **vt, size_t seek) {
	http_request *r = container_of(vt, http_request, vtable);
	r->notify = NULL;
	if (r->connection) {
		(*r->connection)->finish_read_request(r->connection, r, seek);
	}
}

static const hq_source_class http_request_vtable = {
	&close_read_request,
	&start_read_request,
	&finish_read_request,
};

void init_http_request(http_request *r) {
	memset(r, 0, sizeof(*r));
	r->vtable = &http_request_vtable;
}

