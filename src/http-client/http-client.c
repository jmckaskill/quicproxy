#include <cutils/poll.h>
#include <cutils/flag.h>
#include <cutils/apc.h>
#include <cutils/timer.h>
#include <cutils/log.h>

tick_t get_tick() {
	return (tick_t)(monotonic_ns() / 1000);
}

static void on_event(async_socket *s, int flags) {
	LOG(&stderr_log, "have event %x", flags);
}

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

	async_socket s = { 0 };
	s.fd = (int) socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	p.vtable->add_socket(&p.vtable, &s, s.fd, &on_event);
	p.vtable->connect(&p.vtable, &s, (struct sockaddr*)&sa, sizeof(sa), NULL, 0);
	p.vtable->poll(&p.vtable, dispatch_apcs(&d, get_tick(), p.vtable->timeout_granularity_ns / 1000));

	free(args);
	return 0;
}