#include "lib/quic.h"
#include <cutils/flag.h>
#include <cutils/socket.h>
#include <cutils/timer.h>


int main(int argc, const char *argv[]) {
	log_t *debug = &stderr_log;
	int port = 8443;
	const char *host = "192.168.168.2";
	flag_int(&port, 0, "port", "NUM", "Port to bind");
	flag_string(&host, 0, "host", "NAME", "Hostname to bind to");
	char **args = flag_parse(&argc, argv, "[arguments]", 0);

	int fd = must_open_server_socket(SOCK_DGRAM, host, port);

	for (;;) {
		struct sockaddr_storage ss;
		struct sockaddr *sa = (struct sockaddr*)&ss;
		socklen_t salen = sizeof(ss);
		char buf[4096];
		int sz = recvfrom(fd, buf, sizeof(buf), 0, sa, &salen);
		if (sz < 0) {
			break;
		}
		tick_t rxtime = (tick_t)(monotonic_nanoseconds() / 1000);

		struct sockaddr_string in;
		print_sockaddr(&in, sa, salen);
		LOG(debug, "RX from %s:%s %d bytes", in.host.c_str, in.port.c_str, sz);
		qconnection_t qc;
		qc_init(&qc);
		qc_process(&qc, buf, sz, sa, salen, rxtime);
	}

	closesocket(fd);
	free(args);
	return 0;
}
