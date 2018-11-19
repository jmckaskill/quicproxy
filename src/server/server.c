#include "lib/quic.h"
#include "lib/pem.h"
#include <cutils/flag.h>
#include <cutils/socket.h>
#include <cutils/timer.h>
#include <cutils/file.h>

static uint32_t get_tick() {
	uint64_t ns = monotonic_ns();
	return (uint32_t)(ns / 1000);
}

struct server_data {
	const char *server_name;
	size_t num_certs;
	qcertificate_t *certs;
	br_skey_decoder_context skey;
	int fd;
};

static log_t *debug;

static int do_send(void *user, const void *buf, size_t len, const struct sockaddr *sa, size_t sasz, tick_t *sent) {
	struct server_data *s = user;
	struct sockaddr_string in;
	print_sockaddr(&in, sa, sasz);
	LOG(debug, "TX to %s:%s %d bytes", in.host.c_str, in.port.c_str, (int)len);

	if (sendto(s->fd, buf, (int)len, 0, sa, (int)sasz) != (int)len) {
		LOG(debug, "TX failed");
		return -1;
	}
	*sent = get_tick();
	return 0;
}

static int do_sign(void *user, uint16_t algo, const uint8_t *data, size_t len, uint8_t *out) {
	struct server_data *s = user;
	br_rsa_pkcs1_sign fn = br_rsa_i62_pkcs1_sign_get();
	if (!fn) {
		fn = &br_rsa_i31_pkcs1_sign;
	}
	const br_rsa_private_key *sk = br_skey_decoder_get_rsa(&s->skey);
	if (!sk || (sk->n_bitlen + 7) / 8 > QUIC_MAX_SIG_SIZE) {
		return -1;
	}
	uint8_t hash[QUIC_MAX_HASH_SIZE];
	br_sha256_context h;
	br_sha256_init(&h);
	br_sha256_update(&h, data, len);
	br_sha256_out(&h, hash);
	if (!fn(BR_HASH_OID_SHA256, hash, br_sha256_SIZE, sk, out)) {
		return -1;
	}
	return (sk->n_bitlen + 7) / 8;
}

static str_t keylog = STR_INIT;
static void log_key(void *user, const char *line) {
	FILE *f = io_fopen(keylog.c_str, "a");
	if (f) {
		fputs(line, f);
		fclose(f);
	}
}

int main(int argc, const char *argv[]) {
	debug = &stderr_log;
	int port = 8443;
	const char *host = NULL;
	str_t cert_file = STR_INIT;
	str_t key_file = STR_INIT;
	str_set(&key_file, "server.key");
	str_set(&cert_file, "server.crt");
	flag_int(&port, 0, "port", "NUM", "Port to bind");
	flag_string(&host, 0, "host", "NAME", "Hostname to bind to");
	flag_path(&cert_file, 0, "cert", "TLS certificates file - server cert must be first");
	flag_path(&key_file, 0, "key", "TLS key file");
	flag_path(&keylog, 0, "keylog", "TLS key log for wireshark decoding");
	char **args = flag_parse(&argc, argv, "[arguments]", 0);

	int fd = must_open_server_socket(SOCK_DGRAM, host, port);
	br_prng_seeder seedfn = br_prng_seeder_system(NULL);


	struct server_data sd;
	sd.fd = fd;
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
			qsigner_rsa_pkcs1_init(&signer.rsa_pkcs1, &TLS_RSA_SIGNATURES, br_skey_decoder_get_rsa(&skey), certs, num_certs);
			break;
		case BR_KEYTYPE_EC:
			qsigner_ecdsa_init(&signer.ecdsa, &TLS_ECDSA_SIGNATURES, br_skey_decoder_get_ec(&skey), certs, num_certs);
			break;
		}
	}

	qcrypto_params_t params = {
		TLS_DEFAULT_GROUPS,
		TLS_DEFAULT_CIPHERS,
		TLS_DEFAULT_SIGNATURES,
	};

	bool connected = false;
	qconnection_t qc;
	uint8_t pktbuf[4096];


	for (;;) {
		struct sockaddr_storage ss;
		struct sockaddr *sa = (struct sockaddr*)&ss;
		socklen_t salen = sizeof(ss);
		char buf[4096];
		int sz = recvfrom(fd, buf, sizeof(buf), 0, sa, &salen);
		if (sz < 0) {
			break;
		}
		tick_t rxtime = get_tick();

		struct sockaddr_string in;
		print_sockaddr(&in, sa, salen);
		LOG(debug, "RX from %s:%s %d bytes", in.host.c_str, in.port.c_str, sz);

		if (connected) {
			uint8_t dest[QUIC_ADDRESS_SIZE];
			if (qc_get_destination(buf, sz, dest) || memcmp(dest, qc.local_id, sizeof(dest))) {
				continue;
			}
			qc_recv(&qc, buf, sz, rxtime);
		} else {
			qconnect_request_t req;
			if (qc_decode_request(&req, buf, sz, rxtime, &params)) {
				LOG(debug, "failed to decode request");
				continue;
			}
			if (qc_init(&qc, seedfn, pktbuf, sizeof(pktbuf))) {
				FATAL(debug, "failed to init connection");
			}
			qc.debug = &stderr_log;
			qc.send = &do_send;
			qc.send_user = &sd;
			if (qc_accept(&qc, &req, &signer, 1)) {
				LOG(debug, "failed to accept request");
			}
		}
	}

	closesocket(fd);
	free(args);
	return 0;
}
