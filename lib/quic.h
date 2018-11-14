#pragma once

#include <cutils/socket.h>
#include <cutils/stopwatch.h>
#include <cutils/log.h>
#include "bearssl_wrapper.h"

#define QUIC_MAX_IDS 8
#define QUIC_MAX_ADDR 3
#define QUIC_MAX_KEYSHARE 2
#define QUIC_TLS_BUF_SIZE 4096
#define QUIC_HANDSHAKE_MAX_PACKETS 8

typedef struct qconnection_id qconnection_id_t;
struct qconnection_id {
	uint8_t len;
	uint8_t id[18];
};

typedef struct qconnection_addr qconnection_addr_t;
struct qconnection_addr {
	size_t len;
	struct sockaddr_storage ss;
};

enum qcrypto_level {
	QC_INITIAL,
	QC_HANDSHAKE,
	QC_PROTECTED,
	QC_NUM_LEVELS,
};

typedef struct qrx_crypto qrx_crypto_t;
struct qrx_crypto {
	enum qcrypto_level level;
	uint64_t off;
	uint8_t *ptr, *end;
	size_t used, have;
	uint8_t buffer[4096];
	uint32_t bitset;
};

typedef struct qtx_crypto qtx_crypto_t;
struct qtx_crypto {
	uint8_t next;
	uint16_t offset;
	uint16_t offsets[QUIC_HANDSHAKE_MAX_PACKETS];
};

typedef struct qslice qslice_t;
struct qslice {
	uint8_t *p;
	uint8_t *e;
};

typedef struct qtx_stream qtx_stream_t;
struct qtx_stream {
	int64_t id;
	uint64_t offset;
	const uint8_t *data;
	size_t len;
	uint64_t max_data_allowed;
};

typedef struct qtx_packet qtx_packet_t;
struct qtx_packet {
	uint64_t offset;
	qtx_stream_t *stream;
	size_t len;
	tick_t sent;
};

#define QUIC_MAX_SECRET_SIZE 32
#define QUIC_MAX_KEY_SIZE 32
#define QUIC_MAX_IV_SIZE 12
#define QUIC_TAG_SIZE 16

typedef struct qkeyset qkeyset_t;
struct qkeyset {
	br_aes_gen_ctr_keys data;
	br_aes_gen_ctr_keys pn;
	br_gcm_context gcm;
	const br_hash_class *digest;
	uint8_t secret[QUIC_MAX_SECRET_SIZE];
	uint8_t pn_key[QUIC_MAX_KEY_SIZE];
	uint8_t data_key[QUIC_MAX_KEY_SIZE];
	uint8_t data_iv[QUIC_MAX_IV_SIZE];
	size_t key_len;
};

typedef struct qtx_buffer qtx_buffer_t;
struct qtx_buffer {
	qtx_packet_t *buf;
	size_t bufsz;
	uint64_t base;
	uint64_t next;
};

typedef struct qrx_buffer qrx_buffer_t;
struct qrx_buffer {
	uint32_t *buf; // bitset - one bit per packet
	size_t bufsz; // in number of packets/bits
	uint64_t base;
	uint64_t next;
};

typedef struct qconnection qconnection_t;
struct qconnection {
	int(*send)(void *user, const void *buf, size_t len, const struct sockaddr *sa, size_t salen, tick_t *sent);
	void *user;

	bool is_client;
	log_t *debug;
	br_hash_compat_context handshake_hash;
	br_hmac_drbg_context rand;
	qconnection_id_t *peer_id, *local_id;
	qconnection_id_t peer_ids[QUIC_MAX_IDS];
	qconnection_id_t local_ids[QUIC_MAX_IDS];
	qconnection_addr_t *peer_addr;
	qconnection_addr_t peer_addrs[3];

	qslice_t groups;
	qslice_t algorithms;
	qslice_t ciphers;

	size_t key_num;
	br_ec_private_key priv_key[QUIC_MAX_KEYSHARE];
	uint8_t priv_key_data[QUIC_MAX_KEYSHARE][BR_EC_KBUF_PRIV_MAX_SIZE];
	br_hash_compat_context tls_hash;

	qkeyset_t rkey[QC_NUM_LEVELS];
	qkeyset_t tkey[QC_NUM_LEVELS];
	uint8_t master_secret[QUIC_MAX_SECRET_SIZE];

	qrx_buffer_t rx;
	qtx_buffer_t tx;

	struct {
		size_t len;
		char c_str[256];
	} server_name;

	qrx_crypto_t rx_crypto;
	qtx_crypto_t tx_crypto[2];

	size_t tx_crypto_len;
	uint8_t tx_crypto_data[QUIC_TLS_BUF_SIZE];
};

int qc_init(qconnection_t *c, br_prng_seeder seedfn, void *pktbuf, size_t bufsz);
void qc_set_stopwatch(qconnection_t *c, stopwatch_t *w);
void qc_set_trust_anchors(qconnection_t *c, const br_x509_trust_anchor *ta, size_t num);

int qc_on_recv(qconnection_t *c, void *buf, size_t len, const struct sockaddr *sa, size_t salen, tick_t rxtime);
void qc_on_accept(qconnection_t *c, const struct sockaddr *sa, size_t sasz);
int qc_connect(qconnection_t *c, const char *host_name, const char *svc_name);

