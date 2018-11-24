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
	uint8_t pktbuf[4096];
	uint8_t txbuf[4096];
	uint8_t rxbuf[4096];
};

static int server_send(const qinterface_t **vt, const void *addr, size_t addrlen, const void *buf, size_t len, qmicrosecs_t *sent) {
	struct server *s = (struct server*) vt;
	struct sockaddr_string in;
	print_sockaddr(&in, (struct sockaddr*)&s->ss, s->salen);
	LOG(debug, "TX to %s:%s %d bytes", in.host.c_str, in.port.c_str, (int)len);

	if (sendto(s->fd, buf, (int)len, 0, (struct sockaddr*)&s->ss, s->salen) != (int)len) {
		LOG(debug, "TX failed");
		return -1;
	}
	*sent = get_tick();
	return 0;
}

static qstream_t *server_open(const qinterface_t **vt, bool unidirectional) {
	struct server *s = (struct server*) vt;
	if (s->stream_opened) {
		return NULL;
	}
	qinit_stream(&s->stream, s->txbuf, sizeof(s->txbuf), s->rxbuf, sizeof(s->rxbuf));
	s->stream_opened = true;
	return &s->stream;
}

static void server_close(const qinterface_t **vt, qstream_t *stream) {
	struct server *s = (struct server*) vt;
	s->stream_opened = false;
}

static void server_read(const qinterface_t **vt, qstream_t *stream) {
	char buf[1024];
	size_t sz = qrx_read(stream, buf, sizeof(buf)-1);
	buf[sz] = 0;
	LOG(debug, "received '%s'", buf);
	qtx_write(stream, "reply ", strlen("reply "));
	qtx_write(stream, buf, sz);
	qtx_set_finish(stream);
}

static const qinterface_t server_interface = {
	&server_send,
	&server_open,
	&server_close,
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

	static const qconnect_params_t params = {
		.groups = TLS_DEFAULT_GROUPS,
		.ciphers = TLS_DEFAULT_CIPHERS,
		.signatures = TLS_DEFAULT_SIGNATURES,
		.bidi_streams = 1,
		.max_data = 4096,
		.stream_data_bidi_remote = 4096,
	};

	struct server s;
	s.vtable = &server_interface;
	s.fd = fd;
	s.stream_opened = false;
	s.connected = false;

	LOG(debug, "starting server");
	qmicrosecs_t timeout = 0;

	for (;;) {
		int polltimeout = -1;
		if (s.connected) {
			qmicrosecs_t now = get_tick();
			int32_t delta = (int32_t)(timeout - now);
			if (delta <= 0) {
				if (qc_timeout(&s.conn, now, &timeout)) {
					s.connected = false;
				}
				continue;
			}
			polltimeout = (delta + 999) / 1000;
		}

		struct pollfd pfd = { .events = POLLIN,.fd = s.fd };
		switch (poll(&pfd, 1, polltimeout)) {
		case -1:
			return 2;
		case 0:
			continue;
		case 1:
			break;
		}

		for (;;) {
			s.salen = sizeof(s.ss);
			char buf[4096];
			int sz = recvfrom(s.fd, buf, sizeof(buf), 0, (struct sockaddr*)&s.ss, &s.salen);
			if (sz < 0) {
				break;
			}
			qmicrosecs_t rxtime = get_tick();

			struct sockaddr_string in;
			print_sockaddr(&in, (struct sockaddr*)&s.ss, s.salen);
			LOG(debug, "RX from %s:%s %d bytes", in.host.c_str, in.port.c_str, sz);

			uint8_t dest[QUIC_ADDRESS_SIZE];
			if (qc_get_destination(buf, sz, dest)) {
				continue;
			}

			if (s.connected && !memcmp(dest, s.id, QUIC_ADDRESS_SIZE)) {
				if (qc_recv(&s.conn, NULL, 0, buf, sz, rxtime, &timeout)) {
					s.connected = false;
				}
			} else if (!s.connected) {
				qconnect_request_t req;
				if (qc_decode_request(&req, buf, sz, rxtime, &params)) {
					LOG(debug, "failed to decode request");
					continue;
				}
				if (qc_init(&s.conn, &s.vtable, br_prng_seeder_system(NULL), s.pktbuf, sizeof(s.pktbuf))) {
					FATAL(debug, "failed to init connection");
				}
				s.conn.debug = &stderr_log;
				if (keylog_path.len) {
					s.conn.keylog = open_file_log(&keylogger, keylog_path.c_str);
				}
				if (qc_accept(&s.conn, &req, &signer.vtable, &timeout)) {
					LOG(debug, "failed to accept request");
				}
				memcpy(s.id, req.destination, QUIC_ADDRESS_SIZE);
				s.connected = true;
			}
		}
	}

	closesocket(fd);
	free(args);
	return 0;
}
