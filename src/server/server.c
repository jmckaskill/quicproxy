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

struct server_fd {
	int fd;
	socklen_t sasz;
	struct sockaddr_storage ss;
};

static int do_send(void *user, const void *buf, size_t len, tick_t *sent) {
	struct server_fd *fd = user;
	struct sockaddr_string in;
	print_sockaddr(&in, (struct sockaddr*)&fd->ss, fd->sasz);
	LOG(debug, "TX to %s:%s %d bytes", in.host.c_str, in.port.c_str, (int)len);

	if (sendto(fd->fd, buf, (int)len, 0, (struct sockaddr*)&fd->ss, fd->sasz) != (int)len) {
		LOG(debug, "TX failed");
		return -1;
	}
	*sent = get_tick();
	return 0;
}

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
	br_prng_seeder seedfn = br_prng_seeder_system(NULL);

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

	bool connected = false;
	uint64_t local_id = 0;
	qconnection_t qc;
	uint8_t pktbuf[4096];
	struct server_fd sfd;
	sfd.fd = fd;

	for (;;) {
		sfd.sasz = sizeof(sfd.ss);
		char buf[4096];
		int sz = recvfrom(sfd.fd, buf, sizeof(buf), 0, (struct sockaddr*)&sfd.ss, &sfd.sasz);
		if (sz < 0) {
			break;
		}
		tick_t rxtime = get_tick();

		struct sockaddr_string in;
		print_sockaddr(&in, (struct sockaddr*)&sfd.ss, sfd.sasz);
		LOG(debug, "RX from %s:%s %d bytes", in.host.c_str, in.port.c_str, sz);

		uint64_t dest;
		if (qc_get_destination(buf, sz, &dest)) {
			continue;
		}

		if (connected && dest == local_id) {
			qc_recv(&qc, buf, sz, rxtime);
		} else if (!connected) {
			qconnect_request_t req;
			if (qc_decode_request(&req, buf, sz, rxtime, &TLS_DEFAULT_PARAMS)) {
				LOG(debug, "failed to decode request");
				continue;
			}
			if (qc_init(&qc, seedfn, pktbuf, sizeof(pktbuf))) {
				FATAL(debug, "failed to init connection");
			}
			qc.debug = &stderr_log;
			qc.send = &do_send;
			qc.send_user = &sfd;
			if (keylog_path.len) {
				qc.keylog = open_file_log(&keylogger, keylog_path.c_str);
			}
			if (qc_accept(&qc, &req, &signer.vtable)) {
				LOG(debug, "failed to accept request");
			}
			local_id = req.destination;
			connected = true;
		}
	}

	closesocket(fd);
	free(args);
	return 0;
}
