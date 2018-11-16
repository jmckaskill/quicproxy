#pragma once

#include <cutils/socket.h>
#include <cutils/stopwatch.h>
#include <cutils/log.h>
#include "bearssl_wrapper.h"

#define QUIC_MAX_IDS 8
#define QUIC_MAX_ADDR 3
#define QUIC_MAX_KEYSHARE 2
#define QUIC_MAX_CERTIFICATES 8
#define QUIC_MAX_SIG_SIZE 256
#define QUIC_CRYPTO_BUF_SIZE 4096
#define QUIC_CRYPTO_PACKETS 8
#define QUIC_HELLO_RANDOM_SIZE 32

// TLS signature algorithms
#define RSA_PKCS1_SHA256 0x0401
#define RSA_PKCS1_SHA384 0x0501
#define RSA_PKCS1_SHA512 0x0601
#define ECDSA_SECP256R1_SHA256 0x0403
#define ECDSA_SECP384R1_SHA384 0x0503
#define ECDSA_SECP512R1_SHA512 0x0603
#define ED25519 0x0807
#define ED448 0x0808
#define RSA_PSS_SHA256 0x0809
#define RSA_PSS_SHA384 0x080A
#define RSA_PSS_SHA512 0x080B

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

enum qhandshake_state {
	QC_WAIT_FOR_CLIENT_HELLO,
	QC_WAIT_FOR_SERVER_HELLO,
	QC_WAIT_FOR_CERTIFICATE,
	QC_WAIT_FOR_VERIFY,
	QC_WAIT_FOR_FINISHED,
	QC_RUNNING,
};

typedef struct qslice qslice_t;
struct qslice {
	uint8_t *p;
	uint8_t *e;
};

typedef struct qtx_stream qtx_stream_t;
struct qtx_stream {
	int64_t id;
	uint64_t max_data_allowed;
	uint64_t offset;
	uint8_t *data;
	size_t len;
};

typedef struct qrx_stream qrx_stream_t;
struct qrx_stream {
	int64_t id;
	uint64_t offset;	 // offset into the stream the data pointer is up to
	uint8_t *data;	 // the actual data bytes themselves
	uint32_t *valid; // bitset of whether a byte is valid
	size_t len;      // size left in bytes in the buffer
};

typedef struct qtx_packet qtx_packet_t;
struct qtx_packet {
	uint64_t from, to;	// offset of this packet into the data stream
	qtx_stream_t *stream;
	tick_t sent;
};

#define QUIC_MAX_SECRET_SIZE 32
#define QUIC_MAX_HASH_SIZE 32
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
	uint8_t key_len;
	uint8_t hash_len;
};

typedef struct qpacket_buffer qpacket_buffer_t;
struct qpacket_buffer {
	qtx_packet_t *sent;	// packets sent for retries
	size_t sent_len;	// number of packets in the send buffer
	uint64_t received;	// receive bitset - one bit per packet
	uint64_t rx_next;   // next packet to receive (highest received + 1)
	uint64_t tx_next;   // next packet to send (highest sent + 1)
	qkeyset_t tkey;
	qkeyset_t rkey;
	qtx_stream_t tx_crypto;
	qrx_stream_t rx_crypto;
	size_t rx_crypto_consumed;
	uint32_t rx_crypto_valid[QUIC_CRYPTO_BUF_SIZE / 32];
	uint8_t tx_crypto_buf[QUIC_CRYPTO_BUF_SIZE];
	uint8_t rx_crypto_buf[QUIC_CRYPTO_BUF_SIZE];
};

typedef struct qcertificate qcertificate_t;
struct qcertificate {
	br_x509_certificate x509;
};

typedef int(*quic_send)(void* user, const void *buf, size_t len, const struct sockaddr *sa, size_t salen, tick_t *sent);
typedef void(*quic_log_key)(void *user, const char *line);
typedef const qcertificate_t*(*quic_next_cert)(void *user, const qcertificate_t *prev);
typedef int(*quic_sign)(void *user, uint16_t algo, const uint8_t *text, size_t len, uint8_t *out);
typedef int(*quic_verify_chain)(void *user, const qcertificate_t *chain, size_t len, br_x509_pkey *pk);

typedef struct qconnection qconnection_t;
struct qconnection {
	quic_send send;
	quic_next_cert next_cert;
	quic_sign sign;
	quic_verify_chain verify_chain;
	quic_log_key log_key;
	void *user;

	bool is_client;
	enum qhandshake_state hs_state;
	log_t *debug;
	qconnection_id_t *peer_id, *local_id;
	qconnection_id_t peer_ids[QUIC_MAX_IDS];
	qconnection_id_t local_ids[QUIC_MAX_IDS];
	qconnection_addr_t *peer_addr;
	qconnection_addr_t peer_addrs[3];

	qslice_t groups;
	qslice_t algorithms;
	qslice_t ciphers;
	uint16_t cipher;

	size_t key_num;
	br_ec_private_key priv_key[QUIC_MAX_KEYSHARE];
	uint8_t priv_key_data[QUIC_MAX_KEYSHARE][BR_EC_KBUF_PRIV_MAX_SIZE];
	br_x509_pkey cert_key;

	uint8_t master_secret[QUIC_MAX_SECRET_SIZE];
	uint8_t client_random[QUIC_HELLO_RANDOM_SIZE];
	br_hash_compat_context crypto_hash;
	br_hmac_drbg_context rand;

	qpacket_buffer_t pkts[QC_NUM_LEVELS];

	struct {
		size_t len;
		char c_str[256];
	} server_name;
};

int qc_init(qconnection_t *c, br_prng_seeder seedfn, void *pktbuf, size_t bufsz);
void qc_set_stopwatch(qconnection_t *c, stopwatch_t *w);

int qc_get_destination(void *buf, size_t len, uint8_t **p);
int qc_on_recv(qconnection_t *c, void *buf, size_t len, const struct sockaddr *sa, size_t salen, tick_t rxtime);
void qc_on_accept(qconnection_t *c, const struct sockaddr *sa, size_t sasz);
int qc_connect(qconnection_t *c, int family, const char *host_name, const char *svc_name);
