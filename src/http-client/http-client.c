#include "lib/hq/http.h"
#include "lib/hq/file.h"
#include <cutils/flag.h>
#include <cutils/apc.h>
#include <cutils/timer.h>
#include <cutils/log.h>

tick_t get_tick() {
	return (tick_t)(monotonic_ns() / 1000);
}

int main(int argc, const char *argv[]) {
	char **args = flag_parse(&argc, argv, "[arguments]", 0);

	hq_poll p;
	hq_init_poll(&p);

	dispatcher_t d;
	init_dispatcher(&d, get_tick());

	struct sockaddr_in sa = { 0 };
	sa.sin_family = AF_INET;
	inet_pton(AF_INET, "192.168.168.1", &sa.sin_addr);
	sa.sin_port = htons(80);

	char filebuf[4096];
	hq_file_source fs;
	if (hq_open_file_source(&fs, "test.txt", filebuf, sizeof(filebuf))) {
		return 2;
	}

	char rxbuf[4096];

	const hq_stream_class **sock = p.vtable->new_connection(&p.vtable, (struct sockaddr*)&sa, sizeof(sa), rxbuf, sizeof(rxbuf), NULL, NULL);
	(*sock)->set_source(sock, &fs.vtable);
	for (;;) {
		p.vtable->poll(&p.vtable, &d, get_tick());
	}

	free(args);
	return 0;
}