#include "lib/quic.h"
#include <cutils/flag.h>
#include <cutils/socket.h>


int main(int argc, const char *argv[]) {
	log_t *debug = &stderr_log;
	int port = 8443;
	const char *host = "localhost";
	flag_int(&port, 0, "port", "NUM", "Port to bind");
	flag_string(&host, 0, "host", "NAME", "Hostname to bind to");
	char **args = flag_parse(&argc, argv, "[arguments]", 0);

	int fd = must_open_server_socket(SOCK_DGRAM, host, port);

	for (;;) {
		struct sockaddr_storage ss;
		int salen = sizeof(ss);
		char buf[4096];
		int sz = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr*)&ss, &salen);
		if (sz < 0) {
			break;
		}

		struct sockaddr_string in;
		LOG(debug, "RX from %s:%s %d bytes", in.host.c_str, in.port.c_str, sz);
	}

	closesocket(fd);
	free(args);
	return 0;
}