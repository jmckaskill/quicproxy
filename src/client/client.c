#include "lib/quic.h"
#include "lib/bearssl_wrapper.h"
#include "ssl-roots.h"
#include <cutils/flag.h>
#include <cutils/socket.h>
#include <cutils/timer.h>
#include <cutils/file.h>

#define MAX(x, y)   ((x) > (y) ? (x) : (y))

struct client_data {
	int fd;
	const char *host;
	br_x509_minimal_context x509;
	str_t keylog;
	bool fd_is_ipv4;
};

static uint32_t get_tick() {
	uint64_t ns = monotonic_ns();
	return (uint32_t)(ns / 1000);
}

static int do_send(void *user, const void *buf, size_t len, const struct sockaddr *sa, size_t sasz, tick_t *sent) {
	struct client_data *cd = user;
	if (sendto(cd->fd, buf, (int)len, 0, sa, (int)sasz) != (int)len) {
		return -1;
	}
	*sent = get_tick();
	return 0;
}

static int do_verify_chain(void *user, const qcertificate_t *chain, size_t len, br_x509_pkey *pk) {
	struct client_data *cd = user;
	const br_x509_class **x = &cd->x509.vtable;
	(*x)->start_chain(x, cd->host);
	for (size_t i = 0; i < len; i++) {
		(*x)->start_cert(x, (uint32_t)chain[i].x509.data_len);
		(*x)->append(x, chain[i].x509.data, chain[i].x509.data_len);
		(*x)->end_cert(x);
	}
	return (int)(*x)->end_chain(x);
}

static void log_key(void *user, const char *line) {
	struct client_data *cd = user;
	FILE *f = io_fopen(cd->keylog.c_str, "a");
	if (f) {
		fputs(line, f);
		fclose(f);
	}
}

int main(int argc, const char *argv[]) {
	log_t *debug = &stderr_log;
	struct client_data cc;
	str_init(&cc.keylog);

	const char *port = "8443";
	cc.host = "localhost";
	flag_string(&port, 0, "port", "NUM", "Port to connect to");
	flag_string(&cc.host, 0, "host", "NAME", "Hostname to connect to");
	flag_path(&cc.keylog, 0, "keylog", "TLS key log for wireshark decoding");
	char **args = flag_parse(&argc, argv, "[arguments]", 0);

#ifdef WIN32
	WSADATA wsa;
	WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
	cc.fd = (int) socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	struct sockaddr_in6 in6 = { 0 };
	int family = in6.sin6_family = AF_INET6;
	if (cc.fd < 0 || set_ipv6_only(cc.fd, false) || bind(cc.fd, (struct sockaddr*)&in6, sizeof(in6))) {
		LOG(debug, "failed to bind IP6 - trying IP4 only");
		closesocket(cc.fd);
		cc.fd = (int)socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		struct sockaddr_in in4 = { 0 };
		family = in4.sin_family = AF_INET;
		if (cc.fd < 0 || bind(cc.fd, (struct sockaddr*)&in4, sizeof(in4))) {
			FATAL(debug, "failed to bind IP4");
		}
	}

	br_x509_minimal_init_full(&cc.x509, TAs, TAs_NUM);

	uint8_t pktbuf[4096];
	br_prng_seeder seedfn = br_prng_seeder_system(NULL);
	qconnection_t qc;
	if (qc_init(&qc, seedfn, pktbuf, sizeof(pktbuf))) {
		FATAL(debug, "failed to initialize connection");
	}
	qc.send = &do_send;
	qc.verify_chain = &do_verify_chain;
	qc.user = &cc;
	qc.debug = &stderr_log;
	if (cc.keylog.len) {
		qc.log_key = &log_key;
	}

	if (qc_connect(&qc, family, cc.host, port)) {
		FATAL(debug, "failed to connect to %s:%s", cc.host, port);
	}

	for (;;) {
		struct sockaddr_storage ss;
		struct sockaddr *sa = (struct sockaddr*)&ss;
		socklen_t salen = sizeof(ss);
		char buf[4096];

		int w = recvfrom(cc.fd, buf, sizeof(buf), 0, sa, &salen);
		if (w < 0) {
			LOG(debug, "receive error");
			break;
		} else {
			qc_on_recv(&qc, buf, w, sa, salen, get_tick());
		}
	}

	closesocket(cc.fd);
	free(args);
	return 0;
}

