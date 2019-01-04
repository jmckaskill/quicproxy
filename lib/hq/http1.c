#include "http1.h"
#include <cutils/char-array.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

static int add_encoded(http1_connection *c, const void *data, size_t len) {
	ssize_t w = hq_decode_value(c->txbuf.c_str + c->txbuf.len, sizeof(c->txbuf.c_str) - c->txbuf.len - 1, data, len);
	if (w < 0) {
		return -1;
	}
	ca_setlen(&c->txbuf, c->txbuf.len + w);
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
	ca_clear(&c->txbuf);
	c->txbuf.sent = 0;

	if (c->is_client) {
		const hq_header *method = hq_hdr_first(&r->tx_hdrs, &HQ_METHOD);
		const hq_header *path = hq_hdr_first(&r->tx_hdrs, &HQ_PATH);
		const hq_header *host = hq_hdr_first(&r->tx_hdrs, &HQ_AUTHORITY);
		if (add_header_value(c, method)
			|| ca_add(&c->txbuf, " ")
			|| add_header_value(c, path)
			|| ca_add(&c->txbuf, " HTTP/1.1\r\nhost: ")
			|| add_header_value(c, host)) {
			return -1;
		}
	} else {
		const hq_header *sts = hq_hdr_first(&r->tx_hdrs, &HQ_STATUS);
		if (ca_add(&c->txbuf, "HTTP/1.1 ")
			|| add_header_value(c, sts)
			|| ca_add(&c->txbuf, " ")) {
			return -1;
		}
	}

	for (size_t i = 0; i < r->tx_hdrs.size; i++) {
		const hq_header *h = &r->tx_hdrs.headers[i];
		if (!h->key || hq_is_pseudo_header(h)) {
			continue;
		} else if (ca_add(&c->txbuf, "\r\n")
			|| add_encoded(c, h->key, h->key_len)
			|| ca_add(&c->txbuf, ": ")
			|| add_header_value(c, h)) {
			return -1;
		}
	}

	return ca_add(&c->txbuf, "\r\n\r\n");
}

static bool is_space(char ch) {
	return ch == '\r' || ch == ' ' || ch == '\t';
}

static const char *trim_left(const char *p, const char *e) {
	while (p < e && is_space(p[0])) {
		p++;
	}
	return p;
}

static const char *trim_right(const char *p, const char *e) {
	while (e > p && is_space(e[-1])) {
		e--;
	}
	return e;
}

static const char *skip_word(const char *p, const char *e) {
	while (p < e && !is_space(p[0])) {
		p++;
	}
	return p;
}

static bool next_word(const char **next, slice_t *word) {
	const char *start = *next;
	*next += strcspn(start, ";");

	const char *end = trim_right(start, **next ? *next - 1 : *next);
	start = trim_left(start, end);
	word->c_str = start;
	word->len = end - start;

	return word->len || **next;
}

static int check_headers(http1_connection *c, http_request *r) {
	hq_header_table *tbl = &r->rx_hdrs;
	const hq_header *h = hq_hdr_first(tbl, &HQ_CONTENT_LENGTH);
	if (h) {
		if (hq_hdr_next(tbl, h) != NULL) {
			return -1;
		}
		char *end;
		c->body_remaining = strtoull(h->value, &end, 10);
		if (c->body_remaining == ULLONG_MAX || end != (char*)h->value + h->value_len) {
			return -1;
		}
	} else {
		c->body_remaining = 0;
	}

	for (h = hq_hdr_first(tbl, &HQ_CONNECTION); h != NULL; h = hq_hdr_next(tbl, h)) {
		const char *next = h->value;
		slice_t s;
		while (next_word(&next, &s)) {
			if (str_itest(s, "close")) {
				c->body_remaining = UINT64_MAX;
				c->close_after_request = true;
			}
		}
	}

	return 0;
}

static ssize_t copy_string(http1_connection *c, const char **begin, const char *end) {
	size_t off = c->rxbuf.len;
	size_t len = end - *begin;
	if (ca_add2(&c->rxbuf, *begin, len) || ca_addch(&c->rxbuf, '\0')) {
		return -1;
	}
	*begin = c->rxbuf.c_str + off;
	return len;
}

static ssize_t read_headers(http1_connection *c, http_request *r) {
	size_t minsz = 1;

	for (;;) {
		const void *data;
		ssize_t n = (*c->socket)->read(c->socket, 0, minsz, &data, r->notify.fn, r->notify.user);
		if (n < 0) {
			return n;
		} else if (!n) {
			return r->rx_hdrs.size ? HQ_ERR_TCP_RESET : 0;
		}

		const char *next = data;
		const char *end = next + n;

		for (;;) {
			const char *line = next;
			const char *nl = memchr(next, '\n', end - next);
			if (!nl) {
				(*c->socket)->seek(c->socket, line - (char*)data);
				minsz = end + 1 - line;
				break;
			}

			next = nl + 1;

			if (nl == line || (nl == line + 1 && line[0] == '\r')) {
				if (check_headers(c, r)) {
					return HQ_ERR_INVALID_REQUEST;
				}
				(*c->socket)->seek(c->socket, (int)(next - (char*)data));
				return 0;
			}


			if (r->rx_hdrs.size) {
				const char *colon = memchr(line, ':', nl - line);
				if (!colon) {
					return HQ_ERR_INVALID_REQUEST;
				}
				const char *key_end = trim_right(line, colon);

				uint8_t *key = (uint8_t*)c->rxbuf.c_str + c->rxbuf.len;
				ssize_t keysz = hq_encode_http1_key(key, sizeof(c->rxbuf.c_str) - c->rxbuf.len, line, key_end - line);
				if (keysz <= 0 || keysz > UINT8_MAX) {
					return HQ_ERR_INVALID_REQUEST;
				}
				hq_header h;
				h.key = key;
				h.key_len = (uint8_t)keysz;
				c->rxbuf.len += keysz;

				const char *val_start = trim_left(colon + 1, nl);
				const char *val_end = trim_right(val_start, nl);
				ssize_t valsz = copy_string(c, &val_start, val_end);
				if (valsz < 0) {
					return HQ_ERR_INVALID_REQUEST;
				}
				h.value = val_start;
				h.value_len = (uint16_t)valsz;
				h.flags = 0;
				h.next = 0;
				h.hash = hq_compute_hash(h.key, h.key_len);

				if (hq_hdr_add(&r->rx_hdrs, &h, NULL, 0, 0)) {
					return HQ_ERR_INVALID_REQUEST;
				}

			} else if (c->is_client) {
				// response line
				// HTTP/1.1 200 OK\r
				const char *version = line;
				const char *version_end = skip_word(version, nl);
				const char *status = trim_left(version_end, nl);
				const char *status_end = skip_word(status, nl);
				ssize_t stlen = copy_string(c, &status, status_end);
				if (version == version_end || stlen <= 0 || hq_hdr_add(&r->rx_hdrs, &HQ_STATUS, status, (size_t)stlen, 0)) {
					return HQ_ERR_INVALID_REQUEST;
				}

			} else {
				// request line
				// GET / HTTP/1.1\r
				const char *method = line;
				const char *method_end = skip_word(method, nl);
				const char *path = trim_left(method_end, nl);
				const char *path_end = skip_word(path, nl);
				const char *version = trim_left(path_end, nl);
				const char *version_end = skip_word(version, nl);
				ssize_t mlen = copy_string(c, &method, method_end);
				ssize_t plen = copy_string(c, &path, path_end);
				if (version == version_end || mlen <= 0 || plen <= 0) {
					return HQ_ERR_INVALID_REQUEST;
				}

				slice_t ver = { version, version_end - version };
				if (str_test(ver, "HTTP/0.9") || str_test(ver, "HTTP/1.0")) {
					c->close_after_request = true;
				}

				// TODO parse host as authority
				// parse authority from URL

				if (hq_hdr_add(&r->rx_hdrs, &HQ_PATH, path, plen, 0)
					|| hq_hdr_add(&r->rx_hdrs, &HQ_METHOD, method, mlen, 0)
					|| hq_hdr_add(&r->rx_hdrs, &HQ_SCHEME_HTTP, NULL, 0, 0)) {
					return HQ_ERR_INVALID_REQUEST;
				}
			}
		}
	}
}

static void finish_request(http1_connection *c, int errnum) {
	http_request *r = c->request;
	c->request = NULL;
	r->connection = NULL;
	r->finished = true;

	// finish request tx body
	const hq_source_class **src = r->source;
	if (src) {
		r->source = NULL;
		(*src)->stop(src, errnum);
	}

	// finish request rx body
	hq_continue(&r->notify, errnum);

	// notify socket so it can try for the next request
	hq_continue(&c->notify_socket, 0);
}

static bool is_request_finished(http1_connection *c) {
	return c->body_sent && c->headers_received && !c->body_remaining;
}

static ssize_t app_read(const hq_connection_class **vt, http_request *r, size_t off, size_t minsz, const void **pdata) {
	http1_connection *c = container_of(vt, http1_connection, vtable);
	assert(r == c->request);

	if (!c->socket) {
		return HQ_PENDING;
	}

	if (!c->headers_received) {
		ssize_t n = read_headers(c, r);
		if (n < 0) {
			return n;
		}
		c->headers_received = true;
	}

	if (c->body_remaining) {
		ssize_t n = (*c->socket)->read(c->socket, off, minsz, pdata, r->notify.fn, r->notify.user);
		if (n < 0) {
			return n;
		} else if (!n) {
			return HQ_ERR_TCP_RESET;
		}
		return (ssize_t)MIN((uint64_t)n, c->body_remaining);
	} else {
		// TODO handle chunked data
		return 0;
	}
}

static void app_seek(const hq_connection_class **vt, http_request *r, size_t seek) {
	http1_connection *c = container_of(vt, http1_connection, vtable);
	assert(r == c->request);
	assert(seek <= c->body_remaining);
	c->body_remaining -= seek;
	if (c->socket) {
		(*c->socket)->seek(c->socket, seek);
	}
	if (is_request_finished(c)) {
		finish_request(c, 0);
	}
}

static void app_set_source(const hq_connection_class **vt, http_request *r) {
	http1_connection *c = container_of(vt, http1_connection, vtable);
	assert(r == c->request);
	hq_continue(&c->notify_socket, 0);
}

static void stop_connection(const hq_source_class **vt, int error) {
	http1_connection *c = container_of(vt, http1_connection, stream_vtable);
	hq_cancel(&c->notify_socket);

	http_request *r = c->request;
	if (r && r->source) {
		(*r->source)->stop(r->source, error);
	}
}

static void seek_connection(const hq_source_class **vt, size_t seek) {
	http1_connection *c = container_of(vt, http1_connection, stream_vtable);
	hq_cancel(&c->notify_socket);

	if (c->txbuf.sent < c->txbuf.len) {
		size_t use = MIN(c->txbuf.len - c->txbuf.sent, seek);
		c->txbuf.sent += use;
		seek -= use;
	}

	http_request *r = c->request;
	if (r && r->source) {
		(*r->source)->seek(r->source, seek);
	}
}

static ssize_t read_connection(const hq_source_class **vt, size_t off, size_t minsz, const void **pdata, hq_continue_fn fn, void *user) {
	http1_connection *c = container_of(vt, http1_connection, stream_vtable);
	assert(!c->notify_socket.fn);

	while (c->request) {
		http_request *r = c->request;

		// make sure the request has headers to send
		if (!r->tx_hdrs.size) {
			break;
		} else if (!c->txbuf.len && build_headers(c, r)) {
			return HQ_ERR_INVALID_REQUEST;
		}

		// send header data
		if (c->txbuf.sent < c->txbuf.len) {
			*pdata = c->txbuf.c_str + c->txbuf.sent;
			return c->txbuf.len - c->txbuf.sent;
		}

		// send the body
		ssize_t n = 0;
		if (r->source) {
			n = (*r->source)->read(r->source, off, minsz, pdata, fn, user);
			if (n == HQ_PENDING) {
				break;
			} else if (n > 0) {
				return n;
			}
		}

		// source returned eof or permanent error
		c->body_sent = true;
		r->source = NULL;

		if (n) {
			// permanent error
			finish_request(c, (int)n);
			return n;
		} else if (!n && !is_request_finished(c)) {
			// rx not finished yet
			break;
		}

		// request finished
		finish_request(c, 0);
		if (c->close_after_request) {
			return 0;
		}
		hq_continue(&c->notify_app, 0);
	}

	c->notify_socket.fn = fn;
	c->notify_socket.user = user;
	return HQ_PENDING;
}

static void close_connection(const hq_connection_class **vt) {
	http1_connection *c = container_of(vt, http1_connection, vtable);
	hq_cancel(&c->notify_socket);

	http_request *r = c->request;
	if (r) {
		finish_request(c, HQ_ERR_APP_RESET);
	}

	hq_stop(&c->socket, HQ_ERR_APP_RESET);
}

static int accept_request(const hq_connection_class **vt, http_request *r, hq_continue_fn cb, void *user) {
	http1_connection *c = container_of(vt, http1_connection, vtable);
	if (c->request) {
		c->notify_app.fn = cb;
		c->notify_app.user = user;
		return HQ_PENDING;
	} else if (c->close_after_request) {
		return HQ_ERR_APP_RESET;
	}
	c->request = r;
	r->connection = &c->vtable;
	c->headers_received = false;
	c->headers_sent = false;

	// kick off the request
	hq_continue(&r->notify, 0);
	hq_continue(&c->notify_socket, 0);
	return 0;
}

// This is the interface between the connection and the socket
static const hq_source_class http1_stream_vtable = {
	&stop_connection,
	&read_connection,
	&seek_connection,
};

// This is the interface between the connection and the application
static const hq_connection_class http1_connection_vtable = {
	&close_connection,
	&app_read,
	&app_seek,
	&app_set_source,
	&accept_request,
};

const hq_source_class **init_http1_client(http1_connection *c, const char *hostname) {
	memset(c, 0, sizeof(*c));
	c->vtable = &http1_connection_vtable;
	c->stream_vtable = &http1_stream_vtable;
	c->hostname = hostname;
	c->is_client = true;
	return &c->stream_vtable;
}

const hq_source_class **init_http1_server(http1_connection *c) {
	memset(c, 0, sizeof(*c));
	c->vtable = &http1_connection_vtable;
	c->stream_vtable = &http1_stream_vtable;
	c->is_client = false;
	return &c->stream_vtable;
}

void set_http1_source(http1_connection *c, const hq_source_class **source) {
	c->socket = source;
	if (c->request) {
		hq_continue(&c->request->notify, 0);
	}
}





