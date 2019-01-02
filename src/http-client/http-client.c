#include "lib/hq/http.h"
#include "lib/hq/http1.h"
#include "lib/hq/file.h"
#include <cutils/flag.h>
#include <cutils/apc.h>
#include <cutils/timer.h>
#include <cutils/log.h>

tick_t get_tick() {
	return (tick_t)(monotonic_ns() / 1000);
}

struct client {
	const hq_callback_class *vtable;
	http_request *request;
};

static void request_finished(const hq_callback_class **vt, http_request *r, int errnum) {
	LOG(&stderr_log, "request finished %d", errnum);
}

static http_request *next_request(const hq_callback_class **vt) {
	struct client *c = container_of(vt, struct client, vtable);
	http_request *ret = c->request;
	c->request = NULL;
	return ret;
}

static const hq_callback_class cb_class = {
	NULL,
	&next_request,
	&request_finished,
};

struct log_sink {
	const hq_stream_class *vtable;
	log_t *log;
};

static void notify_log_sink(const hq_stream_class **vt, const hq_stream_class **source, int close) {
	struct log_sink *s = container_of(vt, struct log_sink, vtable);
	LOG(s->log, "notify %d", close);
	while (source) {
		const void *data;
		int n = (*source)->start_read(source, &s->vtable, 1, &data);
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
		fwrite(data, 1, n, stderr);
		(*source)->finish_read(source, n);
	}
}

static const hq_stream_class log_sink_vtable = {
	NULL,
	NULL,
	&notify_log_sink,
};

int main(int argc, const char *argv[]) {
	flag_parse(&argc, argv, "[arguments]", 0);

	hq_poll p;
	hq_init_poll(&p);

	dispatcher_t d;
	init_dispatcher(&d, get_tick());

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


	char rxbuf[4096];
	const hq_stream_class **sock = p.vtable->connect_tcp(&p.vtable, (struct sockaddr*)&sa, sizeof(sa), rxbuf, sizeof(rxbuf), NULL, NULL);

	struct client client = { &cb_class, &r };
	struct log_sink sink = { &log_sink_vtable, &stderr_log };

	http1_connection c;
	start_http1_client(&c, &client.vtable, "192.168.168.1", sock);
	notify_log_sink(&sink.vtable, &r.vtable, 0);

	for (;;) {
		p.vtable->poll(&p.vtable, &d, get_tick());
	}

	return 0;
}