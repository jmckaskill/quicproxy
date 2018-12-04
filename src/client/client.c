#include "lib/connection.h"
#include "lib/pem.h"
#include <cutils/flag.h>
#include <cutils/socket.h>
#include <cutils/timer.h>
#include <cutils/file.h>
#include <cutils/log.h>
#include <cutils/endian.h>

static tick_t get_tick() {
	uint64_t ns = monotonic_ns();
	return (tick_t)(ns / 1000);
}

struct client {
	const qinterface_t *vtable;
	qconnection_t conn[1024];
	int fd;
	qstream_t stream;
	uint8_t txbuf[8192];
	uint8_t rxbuf[8192];
	log_t *debug;
	br_x509_minimal_context x509;
	uint32_t counter;
};

static void client_close(const qinterface_t **vt) {
	exit(2);
}

static int client_send(const qinterface_t **vt, const void *buf, size_t len, const struct sockaddr *sa, socklen_t salen, tick_t *sent) {
	struct client *c = (struct client*) vt;
	LOG(c->debug, "TX %d bytes", (int)len);
	if (send(c->fd, buf, (int)len, 0) != (int)len) {
		LOG(c->debug, "TX failed");
		return -1;
	}
	*sent = get_tick();
	return 0;
}

static void client_received(const qinterface_t **vt, qstream_t *stream) {
	qbuf_consume(&stream->rx, qrx_size(stream));
}

static void client_sent(const qinterface_t **vt, qstream_t *stream) {
	struct client *c = (struct client*) vt;
	while (qtx_size(stream) >= 8) {
		if (c->counter == 1000) {
			qtx_finish(stream);
			break;
		}
		char buf[10];
		sprintf(buf, "%08x\n", c->counter++);
		qtx_write(stream, buf, 9);
	}
	qc_flush(c->conn, stream);
}

static const qinterface_t client_interface = {
	&client_close,
	NULL,
	&client_send,
	NULL,
	NULL,
	&client_received,
	&client_sent,
};

int main(int argc, const char *argv[]) {
	struct client c;
	c.vtable = &client_interface;
	c.debug = &stderr_log;
	c.counter = 0;

	str_t keylog_path = STR_INIT;
	struct file_logger keylog_file;
	str_t ca_file = str_init("ca.crt");
	int port = 8443;
	const char *host = "localhost";

	flag_int(&port, 0, "port", "NUM", "Port to connect to");
	flag_string(&host, 0, "host", "NAME", "Hostname to connect to");
	flag_path(&keylog_path, 0, "keylog", "TLS key log for wireshark decoding");

	flag_parse(&argc, argv, "[arguments]", 0);
	int fd = open_client_socket(SOCK_DGRAM, host, port);
	if (fd < 0 || set_non_blocking(fd)) {
		FATAL(c.debug, "failed to connect to [%s]:%d", host, port);
	}

	{
		mapped_file caf;
		if (map_file(&caf, ca_file.c_str)) {
			FATAL(c.debug, "failed to open CA file '%s'", ca_file.c_str);
		}
		size_t num;
		br_x509_trust_anchor *ta = read_trust_anchors(caf.data, caf.size, &num);
		if (!num) {
			FATAL(c.debug, "failed to read CAs from '%s'", ca_file.c_str);
		}
		br_x509_minimal_init_full(&c.x509, ta, num);
		unmap_file(&caf);
	}

	qconnection_cfg_t params = {
		.groups = TLS_DEFAULT_GROUPS,
		.ciphers = TLS_DEFAULT_CIPHERS,
		.signatures = TLS_DEFAULT_SIGNATURES,
		.max_data = 4096,
		.stream_data_bidi_local = 4096,
		.debug = &stderr_log,
		.keylog = keylog_path.len ? open_file_log(&keylog_file, keylog_path.c_str) : NULL,
		.disable_migration = true,
		.ping_timeout = 180 * 1000 * 1000,
		.idle_timeout = 600 * 1000 * 1000,
	};

	LOG(c.debug, "client start");

	stack_string str;
	dispatcher_t d;
	init_dispatcher(&d, get_tick());

	c.fd = fd;
	if (qc_connect(c.conn, sizeof(c.conn), &d, &c.vtable, &params, "localhost", &c.x509.vtable)) {
		FATAL(c.debug, "failed to connect to [%s]:%d", host, port);
	}
	LOG(c.debug, "");

	qinit_stream(&c.stream, c.txbuf, sizeof(c.txbuf), c.rxbuf, sizeof(c.rxbuf));
	client_sent(&c.vtable, &c.stream);

	for (;;) {
		int timeoutms = dispatch_apcs(&d, get_tick(), 1000);
		struct pollfd pfd = { .events = POLLIN,.fd = fd };
		int w = poll(&pfd, 1, timeoutms);
		if (w < 0) {
			FATAL(c.debug, "poll failed: %s", syserr_string(&str));
		} else if (!w) {
			continue;
		}
		for (;;) {
			char buf[4096];
			int r = recv(fd, buf, sizeof(buf), 0);
			if (r < 0) {
				if (would_block()) {
					break;
				} else if (call_again()) {
					continue;
				} else {
					LOG(c.debug, "recv failed: %s", syserr_string(&str));
					break;
				}
			}
			tick_t rxtime = get_tick();
			LOG(c.debug, "RX %d bytes", r);
			qc_recv(c.conn, buf, r, NULL, 0, rxtime);
			LOG(c.debug, "");
		}
	}
}

