#include "http1.h"

#define IS_CLIENT 1
#define CLOSE_AFTER_REQUEST 2
#define SEND_FINISHED 4
#define RECEIVE_FINISHED 8
#define REQUEST_STARTED 16
#define REQUEST_FINISHED 32

static int add_encoded(http1_connection *c, const void *data, size_t len) {
	ssize_t w = hq_decode_value(c->hsend.c_str + c->hsend.len, sizeof(c->hsend.c_str) - c->hsend.len, data, len);
	if (w < 0) {
		return -1;
	}
	c->hsend.len += w;
	return 0;
}

static int add_header_value(http1_connection *c, const hq_header *h) {
	if (!h) {
		return -1;
	} else if (h->flags & HQ_HEADER_COMPRESSED) {
		return add_encoded(c, h->value, h->value_len);
	} else {
		return ca_add2(&c->hsend, h->value, h->value_len);
	}
}

static int build_headers(http1_connection *c, http_request *r) {
	ca_clear(&c->hsend, 0);
	const hq_header_table *hdrs;

	if (c->flags & IS_CLIENT) {
		hdrs = &r->req_hdrs;
		const hq_header *method = hq_hdr_get(&r->req_hdrs, &HQ_METHOD);
		const hq_header *path = hq_hdr_get(&r->req_hdrs, &HQ_PATH);
		const hq_header *host = hq_hdr_get(&r->req_hdrs, &HQ_AUTHORITY);
		if (add_header_value(c, method)
			|| ca_add(&c->hsend, " ")
			|| add_header_value(c, path)
			|| ca_add(&c->hsend, "HTTP/1.1\r\nhost: ")
			|| add_header_value(c, host)) {
			return -1;
		}
	} else {
		hdrs = &r->resp_hdrs;
		const hq_header *sts = hq_hdr_get(&r->resp_hdrs, &HQ_STATUS);
		if (ca_add(&c->hsend, "HTTP/1.1 ")
			|| add_header_value(c, sts)
			|| ca_add(&c->hsend, " ")) {
			return -1;
		}
	}

	for (size_t i = 0; i < ARRAYSZ(hdrs->headers); i++) {
		const hq_header *h = &hdrs->headers[i];
		if (hq_is_pseudo_header(h)) {
			continue;
		} else if (ca_add(&c->hsend, "\r\n")
			|| add_encoded(c, h->key, h->key_len)
			|| ca_add(&c->hsend, ": ")
			|| add_header_value(c, &h)) {
			return -1;
		}
	}

	return ca_add(&c->hsend, "\r\n\r\n");
}

static void start_next_request(http1_connection *c) {
	c->request = (*c->cb)->next_request(c->cb);
	(*c->socket)->ready(c->socket, &c->stream_vtable, 0);
}

static void check_finished_request(http1_connection *c) {
	if ((c->flags & (SEND_FINISHED | RECEIVE_FINISHED)) == (SEND_FINISHED | RECEIVE_FINISHED)) {
		(*c->cb)->request_finished(c->cb, c->request, (c->flags & REQUEST_STARTED) != 0, (c->flags & REQUEST_FINISHED) != 0);
	}
}

static ssize_t http1_read(const hq_stream_class **vt, const hq_stream_class **sink, size_t off, const void **pdata) {
	http1_connection *c = container_of(vt, http1_connection, stream_vtable);
	assert(sink == c->socket);
	http_request *r = c->request;
	if (!r) {
		return 0;
	}
	if (!c->hsend.len && build_headers(c, r)) {
		return HQ_ERR_INVALID_REQUEST;
	}

	off += c->hsend.used;

	if (off < c->hsend.len) {
		*pdata = c->hsend.c_str + off;
		return c->hsend.len - off;
	} else {
		ssize_t n = r->source ? (*r->source)->read(r->source, &r->vtable, off - c->hsend.len, pdata) : 0;
		if (!n) {
			return (c->flags & CLOSE_AFTER_REQUEST) ? 0 : HQ_PENDING;
		}
		return n;
	}
}

static void http1_finish_read(const hq_stream_class **vt, size_t sz, int close) {
	http1_connection *c = container_of(vt, http1_connection, stream_vtable);
	http_request *r = c->request;
	(void)close;

	c->flags |= REQUEST_STARTED;
	size_t hdrsz = MIN(c->hsend.len - c->hsend.used, sz);
	c->hsend.used += hdrsz;
	sz -= hdrsz;
	if (sz) {
		size_t bodysz = MIN(c->body_to_send, sz);
		c->body_to_send -= bodysz;
		(*r->source)->finish_read(r->source, bodysz);
	}

	check_finished_request(c);
}

static void http1_ready(const hq_stream_class **vt, const hq_stream_class **source, int close) {
	http1_connection *c = container_of(vt, http1_connection, stream_vtable);
	http_request *r = c->request;
	assert(source == c->socket);
	(*r->sink)->ready(r->sink, &r->vtable, close);
}

// This is the interface between the connection and the socket
static const hq_stream_class http1_stream_vtable = {
	&http1_read,
	&http1_finish_read,
	&http1_ready,
};

// This is the interface between the connection and the application
static const hq_connection_class http1_connection_vtable = {
	&http1_close_connection,
	&http1_read_request,
	&http1_finish_read_request,
	&http1_request_ready,
};

void start_http1_client(http1_connection *c, const hq_callback_class **cb, const char *hostname, const hq_stream_class **socket) {
	memset(c, 0, sizeof(*c));
	c->vtable = &http1_connection_vtable;
	c->stream_vtable = &http1_stream_vtable;
	c->cb = cb;
	c->hostname = hostname;
	c->socket = socket;
	c->flags = IS_CLIENT;

	start_next_request(c);
}
