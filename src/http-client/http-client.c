#include "lib/hq/http.h"
#include <cutils/poll.h>
#include <cutils/flag.h>
#include <cutils/apc.h>
#include <cutils/timer.h>
#include <cutils/log.h>

tick_t get_tick() {
	return (tick_t)(monotonic_ns() / 1000);
}

static void on_event(async_socket *s, int flags) {
	LOG(&stderr_log, "have event 0x%x", flags);
}

struct client {
	const hq_callback_class *vtable;
	const async_class **async;
	async_socket sock;
	char sendbuf[32 * 1024];
	size_t start, next;
};

static void client_start_shutdown(const hq_callback_class **vt, int errnum) {
	struct client *c = (struct client*)vt;
	shutdown(c->sock.fd, SHUT_WR);
}

static void client_finish_shutdown(const hq_callback_class **vt) {
	exit(0);
}

static size_t client_send_buffer(const hq_callback_class **vt, void **pbuf) {
	struct client *c = (struct client*)vt;
	*pbuf = c->sendbuf + c->next;
	if (c->start > c->next) {
		return c->start - c->next - 1;
	} else {
		return sizeof(c->sendbuf) - c->next;
	}
}

static ssize_t client_send(const hq_callback_class **vt, size_t len, const struct sockaddr *sa, socklen_t salen, tick_t *psent) {
	struct client *c = (struct client*)vt;
	*psent = get_tick();
	c->next = (c->next + len) % sizeof(c->sendbuf);
	ssize_t w = (*c->async)->write(c->async, &c->sock, c->sendbuf + c->start, (c->start <= c->next) ? (c->next - c->start) : (sizeof(c->sendbuf) - c->start), sa, salen);
	if (w > 0) {
		c->start = (c->start + w) % sizeof(c->sendbuf);
	}
	return w;
}

const hq_callback_class client_cb = {
	&client_start_shutdown,
	&client_finish_shutdown,
	&client_send_buffer,
	&client_send,
	NULL,
	NULL,
};

int main(int argc, const char *argv[]) {
	char **args = flag_parse(&argc, argv, "[arguments]", 0);

	async_poll p;
	async_init_poll(&p);

	dispatcher_t d;
	init_dispatcher(&d, get_tick());

	struct sockaddr_in sa = { 0 };
	sa.sin_family = AF_INET;
	inet_pton(AF_INET, "192.168.168.1", &sa.sin_addr);
	sa.sin_port = htons(80);

	struct client c;
	c.vtable = &client_cb;
	c.async = &p.vtable;
	c.start = 0;
	c.next = 0;

	p.vtable->new_socket(&p.vtable, &c.sock, AF_INET, SOCK_STREAM, IPPROTO_TCP, &on_event);
	p.vtable->connect(&p.vtable, &c.sock, (struct sockaddr*)&sa, sizeof(sa), NULL, 0);
	p.vtable->poll(&p.vtable, dispatch_apcs(&d, get_tick(), p.vtable->timeout_granularity_ns / 1000));

	free(args);
	return 0;
}