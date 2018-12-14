#include "http1.h"

static void set_request_sink(const hq_stream_class **vt, const hq_stream_class **sink) {
	http1_request *r = (http1_request*)vt;
	r->sink = sink;
}

static ssize_t peek_request(const hq_stream_class **vt, size_t off, const void **pdata) {
	http1_request *r = (http1_request*)vt;
}

static void seek_request(const hq_stream_class **vt, size_t sz) {
	http1_request *r = (http1_request*)vt;
}

static void close_request(const hq_stream_class **vt, int errnum) {
	http1_request *r = (http1_request*)vt;
}

static void set_request_source(const hq_stream_class **vt, const hq_stream_class **source) {
	http1_request *r = (http1_request*)vt;
	r->source = source;
}

static void abort_request(const hq_stream_class **vt, int errnum) {
	http1_request *r = (http1_request*)vt;
}

static void notify_request(const hq_stream_class **vt) {
	http1_request *r = (http1_request*)vt;
}


static const hq_stream_class http1_request_vtable = {
	&set_request_sink,
	&peek_request,
	&seek_request,
	&close_request,
	&set_request_source,
	&abort_request,
	&notify_request,
};

hq_header_table *init_http1_request(http1_request *r) {
	memset(r, 0, sizeof(*r));
	r->vtable = &http1_request_vtable;
	return &r->hdrs;
}

static int add_encoded(http1_request *r, const void *data, size_t len) {
	ssize_t w = hq_decode_value(r->hdr.c_str + r->hdr.len, sizeof(r->hdr.c_str) - r->hdr.len, data, len);
	if (w < 0) {
		return -1;
	}
	r->hdr.len += w;
	return 0;
}

static int add_header_value(http1_request *r, const hq_header *h) {
	if (!h) {
		return -1;
	} else if (h->flags & HQ_HEADER_COMPRESSED) {
		return add_encoded(r, h->value, h->value_len);
	} else {
		return ca_add2(&r->hdr, h->value, h->value_len);
	}
}

static int build_headers(http1_request *r) {
	const hq_header *method = hq_hdr_get(&r->hdrs, &HQ_METHOD);
	const hq_header *path = hq_hdr_get(&r->hdrs, &HQ_PATH);
	const hq_header *host = hq_hdr_get(&r->hdrs, &HQ_AUTHORITY);
	if (add_header_value(r, method)
		|| ca_add(&r->hdr, " ")
		|| add_header_value(r, path)
		|| ca_add(&r->hdr, "HTTP/1.1\r\nhost: ")
		|| add_header_value(r, host)) {
		return -1;
	}

	for (size_t i = 0; i < ARRAYSZ(r->hdrs.headers); i++) {
		hq_header *h = &r->hdrs.headers[i];
		if (!h->key) {
			continue;
		} else if (ca_add(&r->hdr, "\r\n")
			|| add_encoded(r, h->key, h->key_len)
			|| ca_add(&r->hdr, ": ")
			|| add_header_value(r, &h)) {
			return -1;
		}
	}

	return ca_add(&r->hdr, "\r\n\r\n");
}

static ssize_t peek_connection_stream(const hq_stream_class **vt, size_t off, const void **pdata) {
	http1_connection *c = container_of(vt, http1_connection, stream_vtable);
	http1_request *r = c->request;
	if (!r) {
		return c->should_close ? 0 : HQ_PENDING;
	}

	off += r->hdr_used;
	if (off < r->hdr.len) {
		*pdata = r->hdr.c_str;
		return r->hdr.len - off;
	}

	if (r->source) {
		ssize_t n = (*r->source)->peek(r->source, off - r->hdr.len, pdata);
		if (n < 0) {
			return n;
		} else if (n > 0) {
			r->remaining = off + n + 1;
			return n;
		}
	}

	r->remaining = off;
	return c->should_close ? 0 : HQ_PENDING;
}

static void seek_connection_stream(const hq_stream_class **vt, size_t sz) {
	http1_connection *c = container_of(vt, http1_connection, stream_vtable);
	http1_request *r = c->request;
	size_t touse = MIN(r->hdr.len - r->hdr_used, sz);
	r->hdr_used += touse;
	sz -= touse;
	if (sz) {
		(*r->source)->seek(r->source, sz);
	}
}

static void close_connection_stream(const hq_stream_class **vt, int errnum) {
	http1_connection *c = container_of(vt, http1_connection, stream_vtable);
}

static void abort_connection_stream(const hq_stream_class **vt, int errnum) {
	http1_connection *c = container_of(vt, http1_connection, stream_vtable);
}

static void notify_connection_stream(const hq_stream_class **vt) {
	http1_connection *c = container_of(vt, http1_connection, stream_vtable);
}

static void add_request(const hq_connection_class **vt, const hq_stream_class **request) {
	http1_connection *c = container_of(vt, http1_connection, vtable);
	assert(*request == &http1_request_vtable);
	http1_request *r = (http1_request*)request;
	r->next = NULL;
	if (c->last) {
		c->last->next = r;
	} else {
		c->request = r;
	}
	c->last = r;
	build_headers(r);
}

static void close_connection(const hq_connection_class **vt, int errnum) {
	http1_connection *c = container_of(vt, http1_connection, vtable);
	if (errnum || c->request) {
		(*c->socket)->abort(c->socket, errnum);
	} else {
		c->should_close = true;
		(*c->socket)->notify(c->socket);
	}
}

static const hq_stream_class http1_stream_vtable = {
	NULL,
	&peek_connection_stream,
	&seek_connection_stream,
	&close_connection_stream,
	NULL,
	&abort_connection_stream,
	&notify_connection_stream,
};

static const hq_connection_class http1_connection_vtable = {
	&close_connection,
	&add_request,
};

void init_http1_connection(http1_connection *c, const hq_callback_class **cb, const char *hostname, const hq_stream_class **socket) {
	memset(c, 0, sizeof(*c));
	c->vtable = &http1_connection_vtable;
	c->stream_vtable = &http1_stream_vtable;
	c->cb = cb;
	c->hostname = hostname;
	c->socket = socket;
	(*socket)->set_sink(socket, &c->stream_vtable);
	(*socket)->set_source(socket, &c->stream_vtable);
}
