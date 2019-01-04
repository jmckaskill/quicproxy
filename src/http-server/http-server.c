#include "lib/hq/http1.h"
#include <cutils/log.h>
#include <stdio.h>

struct connection_data {
	http1_connection c;
	http_request req;
	socklen_t salen;
	struct sockaddr_storage sa;
	const hq_source_class **sock;
	char sockbuf[8192];
};

struct server_data {
	hq_poll p;
	const hq_listen_class **ln;
	char lnbuf[256];
};

static void print_header(log_t *log, const hq_header *h) {
	char key[256];
	ssize_t keysz = hq_decode_value(key, sizeof(key), h->key, h->key_len);
	if (keysz <= 0) {
		return;
	}

	if (h->flags & HQ_HEADER_COMPRESSED) {
		char value[1024];
		ssize_t valsz = hq_decode_value(value, sizeof(value), h->value, h->value_len);
		if (valsz < 0) {
			return;
		}
		LOG(log, "%.*s: %.*s", (int)keysz, key, (int)valsz, value);
	} else {
		LOG(log, "%.*s: %.*s", (int)keysz, key, (int)h->value_len, (char*)h->value);
	}
}

static void process_connection(void *user, int error) {
	struct connection_data *cd = user;
	http_request *r = &cd->req;
	log_t *log = &stderr_log;

	for (;;) {
		// get a request
		if (!r->started) {
			int ret = cd->c.vtable->accept_request(&cd->c.vtable, r, &process_connection, cd);
			if (ret == HQ_PENDING) {
				return;
			} else if (ret) {
				break;
			}
		}

		// get the request headers
		if (!r->rx_hdrs.size) {
			int ret = wait_http_headers(&cd->req, &process_connection, cd);
			if (ret == HQ_PENDING) {
				return;
			} else if (ret) {
				break;
			}
		}

		// set the response headers
		if (!r->tx_hdrs.size) {
			for (size_t i = 0; i < r->rx_hdrs.size; i++) {
				print_header(log, &r->rx_hdrs.headers[i]);
			}
			hq_hdr_set(&r->tx_hdrs, &HQ_STATUS_200, NULL, 0, 0);
			hq_hdr_set(&r->tx_hdrs, &HQ_CONTENT_LENGTH_0, NULL, 0, 0);
			set_http_source(r, NULL);
		}

		// consume the request body
		ssize_t n;
		do {
			const void *data;
			n = r->body->read(&r->body, 0, 1, &data, &process_connection, cd);
			if (n == HQ_PENDING) {
				return;
			} else if (n < 0) {
				LOG(log, "read error %d", n);
				return;
			}

			LOG(log, "read %d", (int)n);
			fprintf(stderr, "%.*s\n", (int)n, (char*)data);
			r->body->seek(&r->body, (size_t)n);
		} while (n);

		// wait for the request to complete
		if (!r->finished) {
			int ret = wait_http_complete(r, &process_connection, cd);
			if (ret == HQ_PENDING) {
				return;
			} else if (ret) {
				break;
			}
		}

		init_http_request(r);
	}

	cd->c.vtable->close(&cd->c.vtable);
	free(cd);
}

static void accept_connection(void *user, int error) {
	struct server_data *sd = user;

	for (;;) {
		struct connection_data *cd = malloc(sizeof(struct connection_data));
		cd->salen = sizeof(cd->sa);
		const hq_source_class **tx = init_http1_server(&cd->c);
		cd->sock = (*sd->ln)->accept(sd->ln, cd->sockbuf, sizeof(cd->sockbuf), (struct sockaddr*)&cd->sa, &cd->salen, tx, &accept_connection, sd);
		if (!cd->sock) {
			free(cd);
			break;
		}
		set_http1_source(&cd->c, cd->sock);
		init_http_request(&cd->req);
		process_connection(cd, 0);
	}
}

int main() {
	struct server_data sd = { 0 };
	hq_init_poll(&sd.p);

	struct sockaddr_in sa = { 0 };
	sa.sin_family = AF_INET;
	sa.sin_port = htons(8080);

	sd.ln = sd.p.vtable->listen_tcp(&sd.p.vtable, sd.lnbuf, sizeof(sd.lnbuf), (struct sockaddr*)&sa, sizeof(sa));
	accept_connection(&sd, 0);

	while (!sd.p.vtable->poll(&sd.p.vtable)) {
	}

	return 0;
}