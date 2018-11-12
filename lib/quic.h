#pragma once

#include <cutils/socket.h>
#include <cutils/stopwatch.h>
#include <cutils/log.h>
#include "bearssl_wrapper.h"

#define QUIC_MAX_IDS 8
#define QUIC_MAX_ADDR 3

typedef struct qconnection qconnection_t;
typedef struct qstream qstream_t;
typedef struct qconnection_id qconnection_id_t;
typedef struct qconnection_addr qconnection_addr_t;

struct qconnection_id {
	uint8_t len;
	uint8_t id[18];
};

struct qconnection_addr {
	size_t len;
	struct sockaddr_storage ss;
};

struct qconnection {
	int(*send)(void *user, const void *buf, size_t len, const struct sockaddr *sa, size_t salen, tick_t *sent);
	void *user;

	log_t *debug;
	br_hash_compat_context handshake_hash;
	br_hmac_drbg_context rand;
	qconnection_id_t *peer_id, *local_id;
	qconnection_id_t peer_ids[QUIC_MAX_IDS];
	qconnection_id_t local_ids[QUIC_MAX_IDS];
	qconnection_addr_t *peer_addr;
	qconnection_addr_t peer_addrs[3];
	struct {
		size_t len;
		char c_str[256];
	} server_name;
};

void qc_init_client(qconnection_t *c);
void qc_init_server(qconnection_t *c, const struct sockaddr *sa, size_t sasz, const void *localid, size_t lsz, const void *peerid, size_t psz);
int qc_lookup_peer_name(qconnection_t *c, const char *server_name, const char *svc_name);
void qc_add_peer_address(qconnection_t *c, const struct sockaddr *sa, size_t sasz);
int qc_seed_prng(qconnection_t *c, br_prng_seeder seedfn);
void qc_generate_ids(qconnection_t *c);
void qc_set_stopwatch(qconnection_t *c, stopwatch_t *w);
void qc_set_trust_anchors(qconnection_t *c, const br_x509_trust_anchor *ta, size_t num);
int qc_process(qconnection_t *c, const void *buf, size_t len, const struct sockaddr *sa, size_t salen, tick_t rxtime);
int qc_send_client_hello(qconnection_t *c);

