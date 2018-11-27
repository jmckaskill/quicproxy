#include "lib/connection.h"
#include "lib/pem.h"
#include <cutils/flag.h>
#include <cutils/socket.h>
#include <cutils/timer.h>
#include <cutils/file.h>
#include <cutils/log.h>

static uint32_t get_tick() {
	uint64_t ns = monotonic_ns();
	return (uint32_t)(ns / 1000);
}

static log_t *debug;

struct server {
	const qinterface_t *vtable;
	uint8_t id[QUIC_ADDRESS_SIZE];
	bool connected;
	int fd;
	socklen_t salen;
	struct sockaddr_storage ss;
	qconnection_t conn;
	qstream_t stream;
	bool stream_opened;
	qtx_packet_t pktbuf[256];
	uint8_t txbuf[4096];
	uint8_t rxbuf[4096];
};

static void server_close(const qinterface_t **vt) {
	struct server *s = (struct server*) vt;
	s->connected = false;
	s->stream_opened = false;
}

static int server_send(const qinterface_t **vt, const void *addr, const void *buf, size_t len, tick_t *sent) {
	struct server *s = (struct server*) vt;
	stack_string str;
	LOG(debug, "TX to %s %d bytes", sockaddr_string(&str, (struct sockaddr*)(addr ? addr : &s->ss), s->salen), (int)len);

	if (sendto(s->fd, buf, (int)len, 0, (struct sockaddr*)(addr ? addr : &s->ss), s->salen) != (int)len) {
		LOG(debug, "TX failed");
		return -1;
	}
	*sent = get_tick();
	return 0;
}

static qstream_t *server_open_stream(const qinterface_t **vt, bool unidirectional) {
	struct server *s = (struct server*) vt;
	if (s->stream_opened) {
		return NULL;
	}
	qinit_stream(&s->stream, s->txbuf, sizeof(s->txbuf), s->rxbuf, sizeof(s->rxbuf));
	s->stream_opened = true;
	return &s->stream;
}

static void server_close_stream(const qinterface_t **vt, qstream_t *stream) {
	struct server *s = (struct server*) vt;
	s->stream_opened = false;
}

static void server_read(const qinterface_t **vt, qstream_t *stream) {
	struct server *s = (struct server*) vt;
	char buf[1024];
	size_t sz = qrx_read(stream, buf, sizeof(buf)-1);
	buf[sz] = 0;
	LOG(debug, "received '%s'", buf);
	qtx_write(stream, "reply ", strlen("reply "));
	qtx_write(stream, buf, sz);
	qtx_set_finish(stream);
	qc_flush_stream(&s->conn, stream);
}

static const qinterface_t server_interface = {
	&server_close,
	NULL,
	&server_send,
	&server_open_stream,
	&server_close_stream,
	&server_read,
	NULL,
};

int main(int argc, const char *argv[]) {
	debug = &stderr_log;
	int port = 8443;
	const char *host = NULL;
	str_t cert_file = STR_INIT;
	str_t key_file = STR_INIT;
	str_t keylog_path = STR_INIT;
	struct file_logger keylogger;

	str_set(&key_file, "server.key");
	str_set(&cert_file, "server.crt");
	flag_int(&port, 0, "port", "NUM", "Port to bind");
	flag_string(&host, 0, "host", "NAME", "Hostname to bind to");
	flag_path(&cert_file, 0, "cert", "TLS certificates file - server cert must be first");
	flag_path(&key_file, 0, "key", "TLS key file");
	flag_path(&keylog_path, 0, "keylog", "TLS key log for wireshark decoding");

	char **args = flag_parse(&argc, argv, "[arguments]", 0);

	int fd = must_open_server_socket(SOCK_DGRAM, host, port);
	set_non_blocking(fd);

	br_skey_decoder_context skey;
	br_x509_certificate *certs;
	size_t num_certs;
	qsigner_compat signer;

 	{
		mapped_file cf;
		if (map_file(&cf, cert_file.c_str)) {
			FATAL(debug, "failed to open TLS certificates file '%s'", cert_file.c_str);
		}
		certs = read_pem_certs(cf.data, cf.size, &num_certs);
		if (!certs) {
			FATAL(debug, "failed to read TLS certificates from '%s'", cert_file.c_str);
		}
		unmap_file(&cf);
	}

	{
		mapped_file kf;
		if (map_file(&kf, key_file.c_str)) {
			FATAL(debug, "failed to open TLS key file '%s'", key_file.c_str);
		}
		if (read_pem_key(&skey, kf.data, kf.size)) {
			FATAL(debug, "failed to read TLS key from '%s'", key_file.c_str);
		}
		unmap_file(&kf);
		switch (br_skey_decoder_key_type(&skey)) {
		case BR_KEYTYPE_RSA:
			if (qsigner_rsa_pkcs1_init(&signer.rsa_pkcs1, TLS_RSA_PKCS1_SIGNATURES, br_skey_decoder_get_rsa(&skey), certs, num_certs)) {
				LOG(debug, "failed to load TLS key");
			}
			break;
		case BR_KEYTYPE_EC:
			if (qsigner_ecdsa_init(&signer.ecdsa, TLS_ECDSA_SIGNATURES, br_skey_decoder_get_ec(&skey), certs, num_certs)) {
				LOG(debug, "failed to load TLS key");
			}
			break;
		}
	}

	qconnection_cfg_t params = {
		.groups = TLS_DEFAULT_GROUPS,
		.ciphers = TLS_DEFAULT_CIPHERS,
		.signatures = TLS_DEFAULT_SIGNATURES,
		.bidi_streams = 1,
		.max_data = 4096,
		.stream_data_bidi_remote = 4096,
		.debug = &stderr_log,
		.keylog = keylog_path.len ? open_file_log(&keylogger, keylog_path.c_str) : NULL,
	};

	dispatcher_t d;
	init_dispatcher(&d);

	struct server s;
	s.vtable = &server_interface;
	s.fd = fd;
	s.stream_opened = false;
	s.connected = false;

	stack_string str;
	LOG(debug, "starting server");

	for (;;) {
		int timeoutms = dispatch_apcs(&d, get_tick(), 1000);
		struct pollfd pfd = { .events = POLLIN,.fd = s.fd };
		int w = poll(&pfd, 1, timeoutms);
		if (w < 0) {
			FATAL(debug, "poll failed: %s", syserr_string(&str));
		} else if (!w) {
			continue;
		}

		for (;;) {
			struct sockaddr_storage ss;
			socklen_t salen = sizeof(ss);
			char buf[4096];
			int sz = recvfrom(s.fd, buf, sizeof(buf), 0, (struct sockaddr*)&ss, &salen);
			if (sz < 0) {
				if (would_block()) {
					break;
				} else if (call_again()) {
					continue;
				}
				FATAL(debug, "recv failed: %s", syserr_string(&str));
			}

			tick_t rxtime = get_tick();
			LOG(debug, "RX from %s %d bytes", sockaddr_string(&str, (struct sockaddr*)&ss, salen), sz);

			uint8_t dest[QUIC_ADDRESS_SIZE];
			if (qc_get_destination(buf, sz, dest)) {
				continue;
			}

			if (s.connected && !memcmp(dest, s.id, QUIC_ADDRESS_SIZE)) {
				qc_recv(&s.conn, NULL, buf, sz, rxtime );
			} else if (!s.connected) {
				qconnect_request_t req;
				if (qc_decode_request(&req, buf, sz, rxtime, &params)) {
					LOG(debug, "failed to decode request");
					continue;
				}
				s.salen = salen;
				memcpy(&s.ss, &ss, salen);
				if (qc_accept(&s.conn, &d, &s.vtable, &req, &signer.vtable, s.pktbuf, sizeof(s.pktbuf)/sizeof(s.pktbuf[0]))) {
					LOG(debug, "failed to accept request");
					continue;
				}
				memcpy(s.id, req.destination, QUIC_ADDRESS_SIZE);
				s.connected = true;
			}

			LOG(debug, "");
		}
	}

	closesocket(fd);
	free(args);
	return 0;
}
