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
	hq_header_table *tbl = (c->is_client) ? &r->tx_hdrs : &r->rx_hdrs;
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

static int read_headers(http1_connection *c, http_request *r) {
	hq_header_table *tbl = (c->is_client) ? &r->tx_hdrs : &r->rx_hdrs;
	int minsz = 1;

	for (;;) {
		const void *data;
		int n = (*c->socket)->start_read(c->socket, &c->stream_vtable, minsz, &data);
		if (n < 0) {
			return n;
		} else if (!n) {
			return HQ_ERR_INVALID_REQUEST;
		}

		const char *next = data;
		const char *end = next + n;

		for (;;) {
			const char *line = next;
			const char *nl = memchr(next, '\n', end - next);
			if (!nl) {
				(*c->socket)->finish_read(c->socket, (int)(line - (char*)data));
				minsz = (int)(end + 1 - line);
				break;
			}

			next = nl + 1;

			if (nl == line || (nl == line + 1 && line[0] == '\r')) {
				if (check_headers(c, r)) {
					return HQ_ERR_INVALID_REQUEST;
				}
				(*c->socket)->finish_read(c->socket, (int)(next - (char*)data));
				return 0;
			}


			if (tbl->size) {
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

				size_t buf_len = c->rxbuf.len;
				const char *val_start = trim_left(colon + 1, nl);
				const char *val_end = trim_right(val_start, nl);
				if (ca_add2(&c->rxbuf, val_start, val_end - val_start)) {
					return HQ_ERR_INVALID_REQUEST;
				}
				h.value = c->rxbuf.c_str + buf_len;
				h.value_len = (uint16_t)(c->rxbuf.len - buf_len);
				h.flags = 0;
				h.next = 0;
				h.hash = hq_compute_hash(h.key, h.key_len);

				if (ca_addch(&c->rxbuf, '\0') || hq_hdr_add(tbl, &h, NULL, 0, 0)) {
					return HQ_ERR_INVALID_REQUEST;
				}

			} else if (c->is_client) {
				// response line
				// HTTP/1.1 200 OK\r
				const char *version = line;
				const char *version_end = skip_word(version, nl);
				const char *status = trim_left(version_end, nl);
				const char *status_end = skip_word(status, nl);
				if (version == version_end || status == status_end || hq_hdr_add(&r->tx_hdrs, &HQ_STATUS, status, status_end - status, 0)) {
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
				if (method == method_end || path == path_end || version == version_end) {
					return HQ_ERR_INVALID_REQUEST;
				}

				slice_t ver = { version, version_end - version };
				if (str_test(ver, "HTTP/0.9") || str_test(ver, "HTTP/1.0")) {
					c->close_after_request = true;
				}

				// TODO parse host as authority
				// parse authority from URL

				if (hq_hdr_add(&r->rx_hdrs, &HQ_PATH, path, path_end - path, 0)
					|| hq_hdr_add(&r->rx_hdrs, &HQ_METHOD, method, method_end - method, 0)
					|| hq_hdr_add(&r->rx_hdrs, &HQ_SCHEME_HTTP, NULL, 0, 0)) {
					return HQ_ERR_INVALID_REQUEST;
				}
			}
		}
	}
}


static bool check_finished_request(http1_connection *c, int errnum) {
	if (errnum || (c->body_sent && c->headers_received && !c->body_remaining)) {
		http_request *r = c->request;
		if (r->source) {
			(*r->source)->finish_read(r->source, errnum);
		}
		http_request_ready(r, errnum);
		r->connection = NULL;
		r->finished = true;
		(*c->cb)->request_finished(c->cb, c->request, errnum);
		c->request = NULL;
		if (c->socket_pending) {
			c->socket_pending = false;
			(*c->socket)->read_finished(c->socket, NULL, 0);
		}
		return true;
	} else {
		return false;
	}
}

static int app_start_read(const hq_connection_class **vt, http_request *r, int minsz, const void **pdata) {
	http1_connection *c = container_of(vt, http1_connection, vtable);
	assert(r == c->request);

	if (!c->headers_received) {
		int n = read_headers(c, r);
		if (n < 0) {
			return n;
		}
		c->headers_received = true;
	}

	if (c->body_remaining) {
		int n = (*c->socket)->start_read(c->socket, &c->stream_vtable, minsz, pdata);
		if (n < 0) {
			return n;
		} else if (!n) {
			return HQ_ERR_TCP_RESET;
		}
		return (int)MIN((uint64_t)n, c->body_remaining);
	} else {
		// TODO handle chunked data
		return 0;
	}
}

static void app_finish_read(const hq_connection_class **vt, http_request *r, int finished) {
	http1_connection *c = container_of(vt, http1_connection, vtable);
	assert(r == c->request);
	if (finished >= 0) {
		assert(finished <= c->body_remaining);
		c->body_remaining -= finished;
		(*c->socket)->finish_read(c->socket, finished);
	} else {
		// TODO allow app to close out small requests early
		c->body_remaining = 0;
		(*c->socket)->finish_read(c->socket, finished);
	}
	check_finished_request(c, 0);
}

static void app_read_finished(const hq_connection_class **vt, http_request *r, int close) {
	http1_connection *c = container_of(vt, http1_connection, vtable);
	assert(r == c->request);
	if (c->socket_pending) {
		c->socket_pending = false;
		(*c->socket)->read_finished(c->socket, &c->stream_vtable, close);
	}
}

static int read_next_request(http1_connection *c, const void **pdata) {
	if (!c->close_after_request) {
		c->request = (*c->cb)->next_request(c->cb);
	}
	if (!c->request) {
		return 0;
	}
	http_request *r = c->request;
	r->connection = &c->vtable;

	// kick off reading the request
	http_request_ready(r, 0);

	// kick off sending the headers
	if (!r->tx_hdrs.size) {
		c->socket_pending = true;
		return HQ_PENDING;
	} else if (build_headers(c, r)) {
		return HQ_ERR_INVALID_REQUEST;
	} else {
		*pdata = c->txbuf.c_str;
		return (int)c->txbuf.len;
	}
}

static int socket_start_read(const hq_stream_class **vt, const hq_stream_class **sink, int minsz, const void **pdata) {
	http1_connection *c = container_of(vt, http1_connection, stream_vtable);
	http_request *r = c->request;
	assert(sink == c->socket);
	if (!r) {
		return read_next_request(c, pdata);
	} else if (c->txbuf.sent < c->txbuf.len) {
		*pdata = c->txbuf.c_str + c->txbuf.sent;
		return (int)(c->txbuf.len - c->txbuf.sent);
	} else {
		int n = 0;
		if (r->source) {
			n = (*r->source)->start_read(r->source, &r->vtable, minsz, pdata);
			if (n == HQ_PENDING) {
				return n;
			} else if (n > 0) {
				return n;
			}
		}
		// source returned eof or permanent error
		c->body_sent = true;
		r->source = NULL;
		if (check_finished_request(c, n)) {
			return n ? n : read_next_request(c, pdata);
		} else {
			c->socket_pending = true;
			return HQ_PENDING;
		}
	}
}

static void socket_finish_read(const hq_stream_class **vt, int finished) {
	http1_connection *c = container_of(vt, http1_connection, stream_vtable);
	http_request *r = c->request;
	c->socket_pending = false;

	if (finished < 0) {
		check_finished_request(c, finished);
	} else if (finished <= c->txbuf.len - c->txbuf.sent) {
		c->txbuf.sent += finished;
	} else {
		finished -= (int)(c->txbuf.len - c->txbuf.sent);
		c->txbuf.sent = 0;
		c->txbuf.len = 0;
		(*r->source)->finish_read(r->source, finished);
	}
}

static void socket_read_finished(const hq_stream_class **vt, const hq_stream_class **source, int close) {
	http1_connection *c = container_of(vt, http1_connection, stream_vtable);
	http_request *r = c->request;
	if (close) {
		check_finished_request(c, close);
	} else {
		http_request_ready(r, 0);
	}
}

// This is the interface between the connection and the socket
static const hq_stream_class http1_stream_vtable = {
	&socket_start_read,
	&socket_finish_read,
	&socket_read_finished,
};

// This is the interface between the connection and the application
static const hq_connection_class http1_connection_vtable = {
	&app_start_read,
	&app_finish_read,
	&app_read_finished,
};

void start_http1_client(http1_connection *c, const hq_callback_class **cb, const char *hostname, const hq_stream_class **socket) {
	memset(c, 0, sizeof(*c));
	c->vtable = &http1_connection_vtable;
	c->stream_vtable = &http1_stream_vtable;
	c->cb = cb;
	c->hostname = hostname;
	c->socket = socket;
	c->is_client = true;
	(*socket)->read_finished(socket, &c->stream_vtable, 0);
}
