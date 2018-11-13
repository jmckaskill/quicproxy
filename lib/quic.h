#pragma once

#include <cutils/socket.h>
#include <cutils/stopwatch.h>
#include <cutils/log.h>
#include <cutils/char-array.h>
#include "bearssl_wrapper.h"

#define QUIC_MAX_IDS 8
#define QUIC_MAX_ADDR 3

typedef struct qconnection qconnection_t;
typedef struct qstream qstream_t;
typedef struct qconnection_id qconnection_id_t;
typedef struct qconnection_addr qconnection_addr_t;

enum qstate {
	QC_WAIT_FOR_INITIAL,
	QC_SERVER_HANDSHAKE,
};

struct qconnection_id {
	uint8_t len;
	uint8_t id[18];
};

struct qconnection_addr {
	size_t len;
	struct sockaddr_storage ss;
};

enum qcrypto_level {
	QC_INITIAL,
	QC_HANDSHAKE,
	QC_PROTECTED,
};

struct qcrypto_buffer {
	enum qcrypto_level level;
	uint64_t off;
	uint8_t *ptr, *end;
	size_t used, have;
	uint8_t buffer[4096];
};

struct qconnection {
	enum qstate state;

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

	slice_t groups;
	slice_t algorithms;
	slice_t ciphers;

	enum qcrypto_level tx_level;
	uint64_t tx_next_packet;
	uint64_t tx_crypto_offset;
	struct qcrypto_buffer rx_crypto;

	struct {
		size_t len;
		char c_str[256];
	} server_name;
};

void qc_init(qconnection_t *c);
int qc_lookup_peer_name(qconnection_t *c, const char *server_name, const char *svc_name);
void qc_add_peer_address(qconnection_t *c, const struct sockaddr *sa, size_t sasz);
int qc_seed_prng(qconnection_t *c, br_prng_seeder seedfn);
void qc_generate_ids(qconnection_t *c);
void qc_set_stopwatch(qconnection_t *c, stopwatch_t *w);
void qc_set_trust_anchors(qconnection_t *c, const br_x509_trust_anchor *ta, size_t num);
int qc_process(qconnection_t *c, void *buf, size_t len, const struct sockaddr *sa, size_t salen, tick_t rxtime);
int qc_start_connect(qconnection_t *c);

