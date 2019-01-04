#include "lib/hq/http.h"
#include "lib/hq/http1.h"
#include <cutils/flag.h>
#include <cutils/apc.h>
#include <cutils/timer.h>
#include <cutils/log.h>


struct log_sink {
	http_request *request;
	log_t *log;
};

static void log_request(void *user, int error) {
	struct log_sink *s = user;
	LOG(s->log, "notify %d", error);
	for (;;) {
		const void *data;
		ssize_t n = s->request->body->read(&s->request->body, 0, 1, &data, &log_request, s);
		if (n == HQ_PENDING) {
			return;
		} else if (n < 0) {
			LOG(s->log, "read error %d", n);
			return;
		} else if (!n) {
			LOG(s->log, "read finished");
			return;
		}
		LOG(s->log, "read %d", (int)n);
		fprintf(stderr, "%.*s\n", (int)n, (char*)data);
		s->request->body->seek(&s->request->body, (size_t)n);
	}
}

int main(int argc, const char *argv[]) {
	flag_parse(&argc, argv, "[arguments]", 0);

	hq_poll p;
	hq_init_poll(&p);

	struct sockaddr_in sa = { 0 };
	sa.sin_family = AF_INET;
	inet_pton(AF_INET, "192.168.168.1", &sa.sin_addr);
	sa.sin_port = htons(80);

	http_request r;
	init_http_request(&r);
	hq_hdr_set(&r.tx_hdrs, &HQ_PATH_SLASH, NULL, 0, 0);
	hq_hdr_set(&r.tx_hdrs, &HQ_AUTHORITY, "192.168.168.1", strlen("192.168.168.1"), 0);
	hq_hdr_set(&r.tx_hdrs, &HQ_SCHEME_HTTP, NULL, 0, 0);
	hq_hdr_set(&r.tx_hdrs, &HQ_METHOD_GET, NULL, 0, 0);
	set_http_source(&r, NULL);

	struct log_sink sink = { &r, &stderr_log };

	http1_connection c;
	const hq_source_class **tx = init_http1_client(&c, "192.168.168.1");

	char rxbuf[4096];
	set_http1_source(&c, p.vtable->connect_tcp(&p.vtable, rxbuf, sizeof(rxbuf), (struct sockaddr*)&sa, sizeof(sa), tx));
	c.vtable->accept_request(&c.vtable, &r, NULL, NULL);
	log_request(&sink, 0);

	while (!p.vtable->poll(&p.vtable)) { 
	}

	return 0;
}