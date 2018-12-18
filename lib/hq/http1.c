#include "http1.h"

#define IS_CLIENT 1
#define CLOSE_AFTER_REQUEST 2
#define SEND_FINISHED 4
#define RECEIVE_FINISHED 8
#define REQUEST_STARTED 16
#define REQUEST_FINISHED 32
#define CLOSED 64
#define RECEIVED_HEADERS 128
#define IGNORE_RECV 256

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
	(*c->socket)->notify(c->socket, &c->stream_vtable, 0);
}

static void check_finished_request(http1_connection *c) {
	if ((c->flags & (SEND_FINISHED | RECEIVE_FINISHED)) == (SEND_FINISHED | RECEIVE_FINISHED)) {
		(*c->cb)->request_finished(c->cb, c->request, (c->flags & REQUEST_STARTED) != 0, (c->flags & REQUEST_FINISHED) != 0);
	}
}

static ssize_t http1_read(const hq_stream_class **vt, const hq_stream_class **sink, uint64_t off, const void **pdata) {
	http1_connection *c = container_of(vt, http1_connection, stream_vtable);
	assert(sink == c->socket);
	http_request *r = c->request;
	if (!r) {
		return 0;
	}
	if (!c->hsend.len && build_headers(c, r)) {
		return HQ_ERR_INVALID_REQUEST;
	}

	if (off < c->hsend.len) {
		*pdata = c->hsend.c_str + (size_t)off;
		return c->hsend.len - (size_t)off;
	} else if (off < c->bsend) {
		ssize_t n = (*r->source)->read(r->source, &r->vtable, off - c->hsend.len, pdata);
		return n ? n : HQ_ERR_INVALID_REQUEST;
	} else {
		return (c->flags & CLOSE_AFTER_REQUEST) ? 0 : HQ_PENDING;
	}
}

static void http1_finish_read(const hq_stream_class **vt, uint64_t off, int close) {
	http1_connection *c = container_of(vt, http1_connection, stream_vtable);
	http_request *r = c->request;
	(void)close;

	if (off) {
		c->flags |= REQUEST_STARTED;
	}

	if (off > c->bsend) {
		(*r->source)->finish_read(r->source, off - c->hsend.len, close);
	} else if (close && r->source) {
		(*r->source)->finish_read(r->source, 0, close);
	}

	check_finished_request(c);
}

static void http1_notify(const hq_stream_class **vt, const hq_stream_class **source, int close) {
	http1_connection *c = container_of(vt, http1_connection, stream_vtable);
	http_request *r = c->request;
	if (close) {
		c->flags |= CLOSED;
	}
	if ((c->flags & (CLOSED|IGNORE_RECV)) == IGNORE_RECV) {
		r->vtable->finish_read(&r->vtable, c->brecv, 0);
	} else if (r && r->sink) {
		(*r->sink)->notify(r->sink, &r->vtable, close);
	}
}

static void http1_close(const hq_connection_class **vt, int errnum) {
	http1_connection *c = container_of(vt, http1_connection, vtable);
	assert(errnum);
	(*c->socket)->notify(&c->stream_vtable, NULL, HQ_ERR_APP_RESET);
	http1_notify(&c->stream_vtable, c->socket, HQ_ERR_APP_RESET);
}

static bool is_space(char ch) {
	return ch == '\r' || ch == ' ' || ch == '\t';
}

static char *trim_left(char *p, char *e) {
	while (p < e && is_space(p[0])) {
		p++;
	}
	return p;
}

static char *trim_right(char *p, char *e) {
	while (e > p && is_space(e[-1])) {
		e--;
	}
	return e;
}

static char *skip_word(char *p, char *e) {
	while (p < e && !is_space(p[0])) {
		p++;
	}
	return p;
}

static int check_headers(http1_connection *c, http_request *r) {
	return 0;
}

static ssize_t read_headers(http1_connection *c, http_request *r) {
	const void *data;
	ssize_t n = (*c->socket)->read(c->socket, &r->vtable, c->hrecv.len, &data);
	if (n < 0) {
		return n;
	} else if (!n) {
		return HQ_ERR_INVALID_REQUEST;
	}

	// copy the next chunk to the header buffer
	n = MIN(n, sizeof(c->hrecv.c_str) - c->hrecv.len - 1);
	memcpy(c->hrecv.c_str + c->hrecv.len, data, n);
	c->hrecv.len += n;
	c->hrecv.c_str[c->hrecv.len] = 0;

	// continue parsing the header buffer line by line
	for (;;) {
		char *line = c->hrecv.c_str + c->parsed;
		char *nl = memchr(line, '\n', c->hrecv.len - c->parsed);
		if (!nl) {
			return HQ_PENDING;
		} else if (nl == line || (nl == line + 1 && line[0] == '\r')) {
			c->hrecv.len = nl - c->hrecv.c_str;
			if (check_headers(c, r)) {
				goto bad_request;
			}
			return 0;
		}

		if (c->parsed) {
			// header line
			char *colon = memchr(line, ':', nl - line);
			if (!colon) {
				goto bad_request;
			}
			ssize_t keysz = hq_encode_http1_key(line, colon - line);
			if (keysz < 0) {
				goto bad_request;
			}
			hq_header hdr = { 0 };
			hdr.key = (uint8_t*)line;
			hdr.key_len = (uint8_t)keysz;
			hdr.hash = hq_compute_hash(hdr.key, hdr.key_len);
			char *s = trim_left(colon + 1, nl);
			char *e = trim_right(s, nl);
			hq_header_table *tbl = (c->flags & IS_CLIENT) ? &r->resp_hdrs : &r->req_hdrs;
			if (hq_hdr_add(tbl, &hdr, s, e - s, 0)) {
				goto bad_request;
			}

		} else if (c->flags & IS_CLIENT) {
			// response line
			char *version = line;
			char *version_end = skip_word(version, nl);
			char *status = trim_left(version_end, nl);
			char *status_end = skip_word(status, nl);
			if (version == version_end || status == status_end) {
				goto bad_request;
			}
			if (hq_hdr_add(&r->resp_hdrs, &HQ_STATUS, status, status_end - status, 0)) {
				goto bad_request;
			}

		} else {
			// request line
			char *method = line;
			char *method_end = skip_word(method, nl);
			char *path = trim_left(method_end, nl);
			char *path_end = skip_word(path, nl);
			char *version = trim_left(path_end, nl);
			char *version_end = skip_word(version, nl);
			if (method == method_end || path == path_end || version == version_end) {
				goto bad_request;
			}
			*version_end = 0;
			c->flags |= (!strcmp(version, "HTTP/0.9") || !strcmp(version, "HTTP/1.0")) ? CLOSE_AFTER_REQUEST : 0;

			// TODO parse host as authority
			// parse authority from URL

			if (hq_hdr_add(&r->req_hdrs, &HQ_PATH, path, path_end - path, 0)
				|| hq_hdr_add(&r->req_hdrs, &HQ_METHOD, method, method_end - method, 0)
				|| hq_hdr_add(&r->req_hdrs, &HQ_SCHEME_HTTP, NULL, 0, 0)) {
				goto bad_request;
			}
		}

		c->parsed = nl - c->hrecv.c_str;
	}

bad_request:
	return HQ_ERR_INVALID_REQUEST;
}

static ssize_t http1_read_request(const hq_connection_class **vt, http_request *r, uint64_t off, const void **pdata) {
	http1_connection *c = container_of(vt, http1_connection, vtable);
	assert(r == c->request);
	if (c->flags & CLOSED) {
		return HQ_ERR_APP_RESET;
	}
	if (!(c->flags & RECEIVED_HEADERS)) {
		ssize_t ret = read_headers(c, r);
		if (ret) {
			return ret;
		}
	}
	return (*c->socket)->read(c->socket, &r->vtable, off + c->hrecv.len, pdata);
}

static void http1_finish_read_request(const hq_connection_class **vt, http_request *r, uint64_t off, int close) {
	http1_connection *c = container_of(vt, http1_connection, vtable);
	assert(r == c->request);
}

static void http1_request_ready(const hq_connection_class **vt, http_request *r, int close) {
	http1_connection *c = container_of(vt, http1_connection, vtable);
	assert(r == c->request);
	(*c->socket)->notify(c->socket, &c->stream_vtable, close);
}

// This is the interface between the connection and the socket
static const hq_stream_class http1_stream_vtable = {
	&http1_read,
	&http1_finish_read,
	&http1_notify,
};

// This is the interface between the connection and the application
static const hq_connection_class http1_connection_vtable = {
	&http1_close,
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
