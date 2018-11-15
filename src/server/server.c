#include "lib/quic.h"
#include <cutils/flag.h>
#include <cutils/socket.h>
#include <cutils/timer.h>
#include <cutils/file.h>

static uint32_t get_tick() {
	uint64_t ns = monotonic_nanoseconds();
	return (uint32_t)(ns / 1000);
}

static int do_send(void *user, const void *buf, size_t len, const struct sockaddr *sa, size_t sasz, tick_t *sent) {
	int *pfd = user;
	if (sendto(*pfd, buf, (int)len, 0, sa, (int)sasz) != (int)len) {
		return -1;
	}
	*sent = get_tick();
	return 0;
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

static int read_pem_certs(const char *path, br_x509_certificate *certs) {
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
		certs[num].data = (unsigned char*)der.c_str;
		certs[num].data_len = der.len;
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
static void log_key(void *user, const char *label, const uint8_t *random, size_t random_size, const uint8_t *secret, size_t secret_size) {
	struct {size_t len; char c_str[512];} buf;
	ca_set(&buf, "\n");
	ca_add(&buf, label);
	ca_addch(&buf, ' ');
	for (size_t i = 0; i < random_size; i++) {
		ca_addf(&buf, "%02x", random[i]);
	}
	ca_addch(&buf, ' ');
	for (size_t i = 0; i < secret_size; i++) {
		ca_addf(&buf, "%02x", random[i]);
	}

	FILE *f = io_fopen(keylog.c_str, "a");
	if (f) {
		fwrite(buf.c_str, 1, buf.len, f);
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

	br_x509_certificate certs[QUIC_MAX_CERTIFICATES];
	int cert_num = read_pem_certs(cert_file.c_str, certs);
	if (cert_num < 0) {
		FATAL(debug, "failed to read TLS certificates from %s", cert_file);
	}

	br_skey_decoder_context skey;
	if (read_pem_key(key_file.c_str, &skey)) {
		FATAL(debug, "failed to read TLS key from %s", key_file);
	}

	qc_set_server_rsa(&qc, certs, cert_num, br_skey_decoder_get_rsa(&skey));

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
			qc.user = &fd;
			if (keylog.len) {
				qc.keylog = &log_key;
			}
		}

		qc_on_recv(&qc, buf, sz, sa, salen, rxtime);
	}

	closesocket(fd);
	free(args);
	return 0;
}
