#include "http.h"

static void stop_request(const hq_source_class **vt, int error) {
	http_request *r = container_of(vt, http_request, body);
	hq_cancel(&r->notify);
	// TODO ... now what?
}

static ssize_t read_request(const hq_source_class **vt, size_t off, size_t minsz, const void **pdata, hq_continue_fn notify, void *user) {
	http_request *r = container_of(vt, http_request, body);
	r->notify.fn = notify;
	r->notify.user = user;
	if (r->finished) {
		return 0;
	} else if (!r->connection) {
		return HQ_PENDING;
	} else {
		return (*r->connection)->start_read_request(r->connection, r, off, minsz, pdata);
	}
}

static void seek_request(const hq_source_class **vt, size_t seek) {
	http_request *r = container_of(vt, http_request, body);
	hq_cancel(&r->notify);
	if (r->connection) {
		(*r->connection)->finish_read_request(r->connection, r, seek);
	}
}

static const hq_source_class http_request_vtable = {
	&stop_request,
	&read_request,
	&seek_request,
};

void init_http_request(http_request *r) {
	memset(r, 0, sizeof(*r));
	r->body = &http_request_vtable;
}

void set_http_source(http_request *r, const hq_source_class **src) {
	r->source = src;
	if (r->connection) {
		(*r->connection)->set_request_source(r->connection, r);
	}
}

int wait_http_headers(http_request *r, hq_continue_fn cb, void *user) {
	if (r->rx_hdrs.size) {
		return 0;
	}
	const void *data;
	ssize_t n = read_request(&r->body, 0, 0, &data, cb, user);
	return (n < 0) ? (int)n : 0;
}

int wait_http_complete(http_request *r, hq_continue_fn cb, void *user) {
	if (r->finished) {
		return 0;
	}
	r->notify.fn = cb;
	r->notify.user = user;
	return HQ_PENDING;
}
