#include "lib/connection.h"
#include "lib/pem.h"
#include <cutils/flag.h>
#include <cutils/socket.h>
#include <cutils/timer.h>
#include <cutils/file.h>
#include <cutils/log.h>

#define MAX(x, y)   ((x) > (y) ? (x) : (y))

static uint32_t get_tick() {
	uint64_t ns = monotonic_ns();
	return (uint32_t)(ns / 1000);
}

struct client {
	const qinterface_t *vtable;
	qconnection_t conn;
	int fd;
	qstream_t stream;
	uint8_t txbuf[4096];
	uint8_t rxbuf[4096];
	uint8_t pktbuf[4096];
};

static int client_send(const qinterface_t **vt, const void *addr, const void *buf, size_t len, tick_t *sent) {
	struct client *c = (struct client*) vt;
	if (send(c->fd, buf, (int)len, 0) != (int)len) {
		return -1;
	}
	*sent = get_tick();
	return 0;
}

static const qinterface_t client_interface = {
	&client_send,
	NULL,
	NULL,
};

int main(int argc, const char *argv[]) {
	log_t *debug = &stderr_log;
	str_t keylog_path = STR_INIT;
	struct file_logger keylog_file;
	str_t ca_file = str_init("ca.crt");
	int port = 8443;
	const char *host = "localhost";
	br_x509_minimal_context x509;

	flag_int(&port, 0, "port", "NUM", "Port to connect to");
	flag_string(&host, 0, "host", "NAME", "Hostname to connect to");
	flag_path(&keylog_path, 0, "keylog", "TLS key log for wireshark decoding");

	char **args = flag_parse(&argc, argv, "[arguments]", 0);
	int fd = open_client_socket(SOCK_DGRAM, host, port);
	if (fd < 0) {
		FATAL(debug, "failed to connect to [%s]:%d", host, port);
	}

	{
		mapped_file caf;
		if (map_file(&caf, ca_file.c_str)) {
			FATAL(debug, "failed to open CA file '%s'", ca_file.c_str);
		}
		size_t num;
		br_x509_trust_anchor *ta = read_trust_anchors(caf.data, caf.size, &num);
		if (!num) {
			FATAL(debug, "failed to read CAs from '%s'", ca_file.c_str);
		}
		br_x509_minimal_init_full(&x509, ta, num);
		unmap_file(&caf);
	}

	static const qconnect_params_t params = {
		.groups = TLS_DEFAULT_GROUPS,
		.ciphers = TLS_DEFAULT_CIPHERS,
		.signatures = TLS_DEFAULT_SIGNATURES,
		.max_data = 4096,
		.stream_data_bidi_local = 4096,
	};

	struct client c;
	c.vtable = &client_interface;
	c.fd = fd;
	if (qc_init(&c.conn, &c.vtable, br_prng_seeder_system(NULL), c.pktbuf, sizeof(c.pktbuf))) {
		FATAL(debug, "failed to initialize connection");
	}
	qinit_stream(&c.stream, c.txbuf, sizeof(c.txbuf), c.rxbuf, sizeof(c.rxbuf));
	qtx_write(&c.stream, "hello world", 11);
	qtx_finish(&c.stream);
	qc_add_stream(&c.conn, &c.stream, true);
	c.conn.debug = &stderr_log;
	if (keylog_path.len) {
		c.conn.keylog = open_file_log(&keylog_file, keylog_path.c_str);
	}

	if (qc_connect(&c.conn, host, &x509.vtable, &params)) {
		FATAL(debug, "failed to connect to [%s]:%d", host, port);
	}

	for (;;) {
		char buf[4096];
		int w = recv(fd, buf, sizeof(buf), 0);
		if (w < 0) {
			LOG(debug, "receive error");
			break;
		} else {
			qc_recv(&c.conn, NULL, buf, w, get_tick());
		}
	}

	closesocket(fd);
	free(args);
	return 0;
}

