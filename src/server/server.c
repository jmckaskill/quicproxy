#include "lib/connection.h"
#include "lib/pem.h"
#include <cutils/flag.h>
#include <cutils/socket.h>
#include <cutils/timer.h>
#include <cutils/file.h>
#include <cutils/log.h>
#include <cutils/hash.h>

static uint32_t get_tick() {
	uint64_t ns = monotonic_ns();
	return (uint32_t)(ns / 1000);
}

static log_t *debug;

typedef struct server server;
typedef struct server_connection server_connection;

struct server {
	struct {
		hash_t h;
		uint64_t *keys;
		server_connection **values;
	} by_id;

	int fd;
};

struct server_connection {
	const qinterface_t *vtable;
	struct server *server;
	uint64_t id;
	qconnection_t conn[1024];
	qstream_t stream;
	bool stream_opened;
	uint8_t txbuf[8192];
	uint8_t rxbuf[8192];
};

static void server_close(const qinterface_t **vt) {
	server_connection *s = (server_connection*) vt;
	REMOVE_HASH(&s->server->by_id, FIND_HASH(&s->server->by_id, s->id));
	free(s);
}

static int server_send(const qinterface_t **vt, const void *buf, size_t len, const struct sockaddr *sa, socklen_t salen, tick_t *sent) {
	server_connection *s = (server_connection*) vt;
	stack_string str;
	LOG(debug, "TX to %s %d bytes", sockaddr_string(&str, sa, salen), (int)len);

	if (sendto(s->server->fd, buf, (int)len, 0, sa, salen) != (int)len) {
		LOG(debug, "TX failed");
		return -1;
	}
	*sent = get_tick();
	return 0;
}

static qstream_t *server_open_stream(const qinterface_t **vt, bool unidirectional) {
	server_connection *s = (server_connection*) vt;
	if (s->stream_opened) {
		return NULL;
	}
	qinit_stream(&s->stream, s->txbuf, sizeof(s->txbuf), s->rxbuf, sizeof(s->rxbuf));
	s->stream_opened = true;
	return &s->stream;
}

static void server_close_stream(const qinterface_t **vt, qstream_t *stream) {
	server_connection *s = (server_connection*) vt;
	s->stream_opened = false;
}

static void echo_stream(server_connection *c, qstream_t *s) {
	size_t flushed = 0;
	size_t have;
	const void *ptr;
	uint64_t off = qrx_offset(s);
	uint64_t end = qrx_max(s);
	if (off < end) {
		while ((have = qbuf_data(&s->rx, off + flushed, end, &ptr)) > 0) {
			size_t written = qtx_write(s, ptr, have);
			qbuf_consume(&s->rx, written);
			flushed += written;
			if (written < have) {
				break;
			}
		}
		if (qrx_eof(s)) {
			qtx_finish(s);
		}
		if (flushed) {
			qc_flush(c->conn, s);
		}
	}
}

static void server_received(const qinterface_t **vt, qstream_t *stream) {
	server_connection *c = (server_connection*) vt;
	echo_stream(c, stream);
}

static void server_sent(const qinterface_t **vt, qstream_t *stream) {
	server_connection *c = (server_connection*)vt;
	echo_stream(c, stream);
}

static const qinterface_t server_vtable = {
	&server_close,
	NULL,
	&server_send,
	&server_open_stream,
	&server_close_stream,
	&server_received,
	&server_sent,
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

	server s = {0};
	s.fd = must_open_server_socket(SOCK_DGRAM, host, port);
	set_non_blocking(s.fd);

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

	br_hmac_drbg_context rand;
	br_hmac_drbg_init(&rand, &br_sha256_vtable, "server", 6);
	br_prng_seeder seedfn = br_prng_seeder_system(NULL);
	seedfn(&rand.vtable);
	uint8_t traffic[32];
	br_hmac_drbg_generate(&rand, traffic, sizeof(traffic));
	qcipher_aes_gcm token_key;
	init_aes_128_gcm(&token_key, traffic);

	qconnection_cfg_t cfg = {
		.groups = TLS_DEFAULT_GROUPS,
		.ciphers = TLS_DEFAULT_CIPHERS,
		.signatures = TLS_DEFAULT_SIGNATURES,
		.bidi_streams = 1,
		.max_data = 4096,
		.stream_data_bidi_remote = 4096,
		.debug = &stderr_log,
		.keylog = keylog_path.len ? open_file_log(&keylogger, keylog_path.c_str) : NULL,
		.server_key = &token_key.vtable,
		.idle_timeout = 1000 * 1000 * 1000,
	};

	dispatcher_t d;
	init_dispatcher(&d, get_tick());

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
			struct sockaddr *sa = (struct sockaddr*) &ss;
			socklen_t salen = sizeof(ss);
			char buf[4096];
			int sz = recvfrom(s.fd, buf, sizeof(buf), 0, sa, &salen);
			if (sz < 0) {
				if (would_block()) {
					break;
				} else if (call_again()) {
					continue;
				}
				FATAL(debug, "recv failed: %s", syserr_string(&str));
			}

			tick_t rxtime = get_tick();
			LOG(debug, "RX from %s %d bytes", sockaddr_string(&str, sa, salen), sz);

			uint64_t dest = qc_get_destination(buf, sz);
			if (!dest) {
				// bogus message
				continue;
			}

			bool added;
			size_t idx = INSERT_HASH(&s.by_id, dest, &added);
			if (!added) {
				server_connection *c = s.by_id.values[idx];
				qc_recv(c->conn, buf, sz, sa, salen, rxtime);
				continue;
			}

			// Time to create a new connection
			cfg.validate_path = s.by_id.h.size > 10;
			qconnect_request_t req;
			if (qc_decode_request(&req, &cfg, buf, sz, sa, salen, rxtime)) {
				LOG(debug, "failed to decode request");
				REMOVE_HASH(&s.by_id, idx);
				continue;
			}

			server_connection *c = malloc(sizeof(server_connection));
			c->id = dest;
			c->server = &s;
			c->vtable = &server_vtable;
			c->stream_opened = false;

			if (qc_accept(c->conn, sizeof(c->conn), &d, &c->vtable, &req, &signer.vtable)) {
				LOG(debug, "failed to accept request");
				free(c);
				REMOVE_HASH(&s.by_id, idx);
				continue;
			}

			s.by_id.values[idx] = c;
			LOG(debug, "accepted new connection");
		}
	}

	closesocket(s.fd);
	free(args);
	return 0;
}
