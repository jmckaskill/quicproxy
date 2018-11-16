#include "lib/quic.h"
#include <cutils/flag.h>
#include <cutils/socket.h>
#include <cutils/timer.h>
#include <cutils/file.h>

static uint32_t get_tick() {
	uint64_t ns = monotonic_nanoseconds();
	return (uint32_t)(ns / 1000);
}

struct server_data {
	const char *server_name;
	qcertificate_t *certs;
	br_skey_decoder_context *skey;
	int fd;
};


static int do_send(void *user, const void *buf, size_t len, const struct sockaddr *sa, size_t sasz, tick_t *sent) {
	struct server_data *s = user;
	if (sendto(s->fd, buf, (int)len, 0, sa, (int)sasz) != (int)len) {
		return -1;
	}
	*sent = get_tick();
	return 0;
}

static const qcertificate_t *get_next_cert(void *user, const qcertificate_t *c) {
	struct server_data *s = user;
	if (!c) {
		c = s->certs;
	} else {
		c++;
	}
	return c->x509.data ? c : NULL;
}

static int do_sign(void *user, uint16_t algo, const uint8_t *data, size_t len, uint8_t *out) {
	struct server_data *s = user;
	br_rsa_pkcs1_sign fn = br_rsa_i62_pkcs1_sign_get();
	if (!fn) {
		fn = &br_rsa_i31_pkcs1_sign;
	}
	const br_rsa_private_key *sk = br_skey_decoder_get_rsa(s->skey);
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

static int pem_to_der(br_pem_decoder_context *pem, str_t *der, mapped_file *mf, size_t *poff) {
	*poff += br_pem_decoder_push(pem, mf->data + *poff, mf->size - *poff);

	if (br_pem_decoder_event(pem) != BR_PEM_BEGIN_OBJ) {
		return -1;
	}

	br_pem_decoder_setdest(pem, (void(*)(void*, const void*, size_t))&str_add2, der);
	*poff += br_pem_decoder_push(pem, mf->data + *poff, mf->size - *poff);
	br_pem_decoder_setdest(pem, NULL, NULL);

	return br_pem_decoder_event(pem) != BR_PEM_END_OBJ;
}

static int read_pem_certs(const char *path, qcertificate_t *certs) {
	mapped_file mf;
	if (map_file(&mf, path)) {
		return -1;
	}

	size_t off = 0;
	int num = 0;
	br_pem_decoder_context pem;
	br_pem_decoder_init(&pem);

	while (off < mf.size && num < QUIC_MAX_CERTIFICATES) {
		str_t der = STR_INIT;
		if (pem_to_der(&pem, &der, &mf, &off)) {
			str_destroy(&der);
			num = -1;
			goto end;
		}
		certs[num].x509.data = (unsigned char*)der.c_str;
		certs[num].x509.data_len = der.len;
		num++;
	}

end:
	unmap_file(&mf);
	return num;
}

static int read_pem_key(const char *path, br_skey_decoder_context *skey) {
	br_skey_decoder_init(skey);

	mapped_file mf;
	if (map_file(&mf, path)) {
		return -1;
	}

	int ret = -1;
	size_t off = 0;
	str_t der = STR_INIT;
	br_pem_decoder_context pem;
	br_pem_decoder_init(&pem);
	if (!pem_to_der(&pem, &der, &mf, &off)) {
		br_skey_decoder_push(skey, der.c_str, der.len);
		ret = br_skey_decoder_last_error(skey);
	}
	str_destroy(&der);
	unmap_file(&mf);
	return ret;
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
	log_t *debug = &stderr_log;
	int port = 8443;
	const char *host = NULL;
	str_t cert_file = STR_INIT;
	str_t key_file = STR_INIT;
	flag_int(&port, 0, "port", "NUM", "Port to bind");
	flag_string(&host, 0, "host", "NAME", "Hostname to bind to");
	flag_path(&cert_file, 0, "cert", "TLS certificates file - server cert must be first");
	flag_path(&key_file, 0, "key", "TLS key file");
	flag_path(&keylog, 0, "keylog", "TLS key log for wireshark decoding");
	char **args = flag_parse(&argc, argv, "[arguments]", 0);

	int fd = must_open_server_socket(SOCK_DGRAM, host, port);
	br_prng_seeder seedfn = br_prng_seeder_system(NULL);

	bool connected = false;
	qconnection_t qc;
	uint8_t pktbuf[4096];
	if (qc_init(&qc, seedfn, pktbuf, sizeof(pktbuf))) {
		FATAL(debug, "failed to init connection");
	}

	qcertificate_t certs[QUIC_MAX_CERTIFICATES+1];
	int cert_num = read_pem_certs(cert_file.c_str, certs);
	if (cert_num < 0) {
		FATAL(debug, "failed to read TLS certificates from %s", cert_file.c_str);
	}
	certs[cert_num].x509.data = NULL;

	br_skey_decoder_context skey;
	if (read_pem_key(key_file.c_str, &skey)) {
		FATAL(debug, "failed to read TLS key from %s", key_file.c_str);
	}

	struct server_data sd;
	sd.certs = certs;
	sd.skey = &skey;
	sd.fd = fd;

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
			uint8_t *dest;
			int dsz = qc_get_destination(buf, sz, &dest);
			if (dsz < 0 || dsz != qc.local_id->len || memcmp(dest, qc.local_id->id, dsz)) {
				continue;
			}
		} else if (!connected) {
			qc_on_accept(&qc, sa, salen);
			qc.debug = &stderr_log;
			qc.send = &do_send;
			qc.next_cert = &get_next_cert;
			qc.sign = &do_sign;
			qc.user = &sd;
			if (keylog.len) {
				qc.log_key = &log_key;
			}
		}

		qc_on_recv(&qc, buf, sz, sa, salen, rxtime);
	}

	closesocket(fd);
	free(args);
	return 0;
}
