#include "lib/quic.h"
#include "lib/bearssl_wrapper.h"
#include <cutils/flag.h>
#include <cutils/socket.h>
#include <cutils/timer.h>

struct client_connection {
	int fd4;
	int fd6;
};

static uint32_t get_tick() {
	uint64_t ns = monotonic_nanoseconds();
	return (uint32_t)(ns / 1000);
}

static int do_send(void *user, const void *buf, size_t len, const struct sockaddr *sa, size_t sasz, tick_t *sent) {
	struct client_connection *c = user;
	int fd = -1;
	switch (sa->sa_family) {
	case AF_INET:
		fd = c->fd4;
		break;
	case AF_INET6:
		fd = c->fd6;
		break;
	}
	if (sendto(fd, buf, (int)len, 0, sa, (int)sasz) != (int)len) {
		return -1;
	}
	*sent = get_tick();
	return 0;
}

int main(int argc, const char *argv[]) {
	log_t *debug = &stderr_log;

	const char *port = "8443";
	const char *host = "localhost";
	flag_string(&port, 0, "port", "NUM", "Port to connect to");
	flag_string(&host, 0, "host", "NAME", "Hostname to connect to");
	char **args = flag_parse(&argc, argv, "[arguments]", 0);

#ifdef WIN32
	WSADATA wsa;
	WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
	struct client_connection cc;
	cc.fd4 = (int) socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	struct sockaddr_in in4 = { 0 };
	in4.sin_family = AF_INET;
	if (bind(cc.fd4, (struct sockaddr*)&in4, sizeof(in4))) {
		FATAL(debug, "failed to bind IP4");
	}

	cc.fd6 = (int) socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	struct sockaddr_in6 in6 = { 0 };
	in6.sin6_family = AF_INET6;
	if (set_ipv6_only(cc.fd6, true) || bind(cc.fd6, (struct sockaddr*)&in6, sizeof(in6))) {
		LOG(debug, "failed to bind IP6");
		closesocket(cc.fd6);
		cc.fd6 = -1;
	}

	qconnection_t qc;
	qc_init(&qc);
	qc.send = &do_send;
	qc.user = &cc;
	qc.debug = &stderr_log;

	br_prng_seeder seedfn = br_prng_seeder_system(NULL);
	if (!seedfn || qc_seed_prng(&qc, seedfn)) {
		FATAL(debug, "system random number generator failed");
	}
	qc_generate_ids(&qc);

	if (qc_lookup_peer_name(&qc, host, port)) {
		FATAL(debug, "failed to lookup %s:%s", host, port);
	}

	if (qc_start_connect(&qc)) {
		FATAL(debug, "failed to send hello");
	}

	closesocket(cc.fd4);
	closesocket(cc.fd6);
	free(args);
	return 0;
}

