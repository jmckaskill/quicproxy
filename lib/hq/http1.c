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
	for (;;) {
		const void *data;
		ssize_t n = (*c->socket)->read(c->socket, &r->vtable, 0, &data);
		if (n < 0) {
			return n;
		} else if (!n) {
			return HQ_ERR_INVALID_REQUEST;
		}

		for (;;) {
			char *nl = memchr(data, '\n', n);
			if (!nl) {
				break;
			}

			data = nl + 1;
			char *colon = s


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

static ssize_t app_read(const hq_connection_class **vt, http_request *r, size_t off, const void **pdata) {
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

static void finish_app_read(const hq_connection_class **vt, http_request *r, size_t finished, int close) {
	http1_connection *c = container_of(vt, http1_connection, vtable);
	assert(r == c->request);
}

static void app_notify(const hq_connection_class **vt, http_request *r, int close) {
	http1_connection *c = container_of(vt, http1_connection, vtable);
	assert(r == c->request);
	(*c->socket)->notify(c->socket, &c->stream_vtable, close);
}



static int add_encoded(http1_connection *c, const void *data, size_t len) {
	ssize_t w = hq_decode_value(c->txbuf.c_str + c->txbuf.len, sizeof(c->txbuf.c_str) - c->txbuf.len, data, len);
	if (w < 0) {
		return -1;
	}
	c->txbuf.len += w;
	return 0;
}

static int add_header_value(http1_connection *c, const hq_header *h) {
	if (!h) {
		return -1;
	} else if (h->flags & HQ_HEADER_COMPRESSED) {
		return add_encoded(c, h->value, h->value_len);
	} else {
		return ca_add2(&c->txbuf, h->value, h->value_len);
	}
}

static int build_headers(http1_connection *c, http_request *r) {
	ca_clear(&c->txbuf, 0);
	c->txbuf.sent = 0;
	const hq_header_table *hdrs;

	if (c->is_client) {
		hdrs = &r->req_hdrs;
		const hq_header *method = hq_hdr_get(&r->req_hdrs, &HQ_METHOD);
		const hq_header *path = hq_hdr_get(&r->req_hdrs, &HQ_PATH);
		const hq_header *host = hq_hdr_get(&r->req_hdrs, &HQ_AUTHORITY);
		if (add_header_value(c, method)
			|| ca_add(&c->txbuf, " ")
			|| add_header_value(c, path)
			|| ca_add(&c->txbuf, "HTTP/1.1\r\nhost: ")
			|| add_header_value(c, host)) {
			return -1;
		}
	} else {
		hdrs = &r->resp_hdrs;
		const hq_header *sts = hq_hdr_get(&r->resp_hdrs, &HQ_STATUS);
		if (ca_add(&c->txbuf, "HTTP/1.1 ")
			|| add_header_value(c, sts)
			|| ca_add(&c->txbuf, " ")) {
			return -1;
		}
	}

	for (size_t i = 0; i < ARRAYSZ(hdrs->headers); i++) {
		const hq_header *h = &hdrs->headers[i];
		if (hq_is_pseudo_header(h)) {
			continue;
		} else if (ca_add(&c->txbuf, "\r\n")
			|| add_encoded(c, h->key, h->key_len)
			|| ca_add(&c->txbuf, ": ")
			|| add_header_value(c, &h)) {
			return -1;
		}
	}

	return ca_add(&c->txbuf, "\r\n\r\n");
}

static bool check_finished_request(http1_connection *c, int errnum) {
	if (errnum || (c->send_finished && c->recv_finished)) {
		http_request *r = c->request;
		if (r->source) {
			(*r->source)->finish_read(r->source, 0, errnum);
		}
		if (r->sink) {
			(*r->sink)->notify(r->sink, NULL, errnum);
		}
		(*c->cb)->request_finished(c->cb, c->request, errnum);
		c->request = NULL;
		return true;
	} else {
		return false;
	}
}

static ssize_t read_next_request(http1_connection *c, const void **pdata) {
	if (!c->close_after_request) {
		c->request = (*c->cb)->next_request(c->cb);
	}
	if (!c->request) {
		return 0;
	}
	http_request *r = c->request;
	if (c->is_client) {
		if (build_headers(c, r)) {
			return HQ_ERR_INVALID_REQUEST;
		}
		*pdata = c->txbuf.c_str;
		return c->txbuf.len;
	} else {
		return HQ_PENDING;
	}
}

static ssize_t socket_read(const hq_stream_class **vt, const hq_stream_class **sink, size_t off, const void **pdata) {
	http1_connection *c = container_of(vt, http1_connection, stream_vtable);
	assert(sink == c->socket && !off);
	http_request *r = c->request;
	if (!r) {
		return read_next_request(c, pdata);
	} else if (off + c->txbuf.sent < c->txbuf.len) {
		*pdata = c->txbuf.c_str + c->txbuf.sent + off;
		return c->txbuf.len - off - c->txbuf.sent;
	} else {
		ssize_t n = r->source ? (*r->source)->read(r->source, &r->vtable, off - c->txbuf.len, pdata) : 0;
		if (n == HQ_PENDING) {
			return n;
		} else if (n > 0) {
			return n;
		}
		r->source = NULL;
		if (check_finished_request(c, (int)n)) {
			return n ? n : read_next_request(c, pdata);
		} else {
			return HQ_PENDING;
		}
	}
}

static void socket_finish_read(const hq_stream_class **vt, size_t finished, int close) {
	http1_connection *c = container_of(vt, http1_connection, stream_vtable);
	http_request *r = c->request;
	size_t hsz = MIN(finished, c->txbuf.len - c->txbuf.sent);
	c->txbuf.sent += hsz;
	finished -= hsz;

	if (close) {
		c->send_finished = true;
		if (r->source) {
			(*r->source)->finish_read(r->source, finished, close);
		}
		check_finished_request(c, 0);
	} else if (finished) {
		assert(r->source);
		(*r->source)->finish_read(r->source, finished, 0);
	}
}

static void socket_notify(const hq_stream_class **vt, const hq_stream_class **source, int close) {
	http1_connection *c = container_of(vt, http1_connection, stream_vtable);
	http_request *r = c->request;
	assert(close || source == c->socket);
	if (close) {
		check_finished_request(c, close);
	} else if (c->recv_ignore) {
		for (;;) {
			const void *data;
			ssize_t n = app_read(&c->vtable, r, 0, &data);
			if (n > 0) {
				finish_app_read(&c->vtable, r, (size_t)n, 0);
			} else {
				break;
			}
		}
	} else if (r->sink) {
		(*r->sink)->notify(r->sink, &r->vtable, 0);
	} else {
		// No sink is hooked up. We'll ignore the notification.
	}
}

// This is the interface between the connection and the socket
static const hq_stream_class http1_stream_vtable = {
	&socket_read,
	&socket_finish_read,
	&socket_notify,
};

// This is the interface between the connection and the application
static const hq_connection_class http1_connection_vtable = {
	&app_close,
	&app_read,
	&finish_app_read,
	&app_notify,
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
