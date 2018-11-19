#pragma once

#include "rx-stream.h"
#include "cipher.h"
#include "packets.h"
#include "signature.h"
#include <cutils/stopwatch.h>
#include <cutils/log.h>
#include "bearssl_wrapper.h"

#define QUIC_MAX_IDS 8
#define QUIC_MAX_ADDR 3
#define QUIC_MAX_CERTIFICATES 8
#define QUIC_MAX_ALGORITHMS 32
#define QUIC_CRYPTO_BUF_SIZE 4096
#define QUIC_CRYPTO_PACKETS 8

#define QUIC_ADDRESS_SIZE 19 // +1 for size

typedef struct qtx_stream qtx_stream_t;
struct qtx_stream {
	int64_t id;
	uint64_t max_data_allowed;
	uint64_t offset;
	uint8_t *data;
	size_t len;
};

typedef struct qtx_packet qtx_packet_t;
struct qtx_packet {
	uint64_t from, to;	// offset of this packet into the data stream
	qtx_stream_t *stream;
	tick_t sent;
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
};

typedef struct qcertificate qcertificate_t;
struct qcertificate {
	br_x509_certificate x509;
};

typedef struct qcrypto_params qcrypto_params_t;
struct qcrypto_params {
	const char *groups;
	const qcipher_class *const *ciphers;
	const qsignature_class *const *signatures;
};

typedef struct qconnection qconnection_t;
typedef int(*quic_send)(void *user, const void *buf, size_t len, tick_t *sent);

struct qconnection {
	// send/recv
	quic_send send;
	void *send_user;
	uint64_t local_id;
	uint8_t peer_id[QUIC_ADDRESS_SIZE];
	bool is_client;

	// crypto management
	qpacket_buffer_t pkts[3];
	uint8_t master_secret[QUIC_MAX_HASH_SIZE];
	uint8_t client_random[QUIC_RANDOM_SIZE];
	uint8_t server_random[QUIC_RANDOM_SIZE];
	br_hmac_drbg_context rand;

	// receiving
	int crypto_state;
	uint64_t rx_crypto_off;
	struct crypto_decoder rx_crypto;
	union {
		struct server_hello server_hello;
		struct verify verify;
		struct finished finished;
	} rx_crypto_data;

	// logging
	log_t *debug;
	log_t *keylog;

	// cipher
	const qcipher_class *cipher;

	// key group
	size_t key_num;
	br_ec_private_key keys[QUIC_MAX_KEYSHARE];
	uint8_t key_data[QUIC_MAX_KEYSHARE][BR_EC_KBUF_PRIV_MAX_SIZE];

	// certificates
	const qsignature_class *signature;
	const br_x509_class **validator;
	const qsigner_class **signer;
	const char *server_name;
	const qcrypto_params_t *params;

	// transcript digest
	union {
		const br_hash_class *vtable;
		br_sha256_context sha256;
		br_sha384_context sha384;
	} msg_hash;
};

int qc_init(qconnection_t *c, br_prng_seeder seedfn, void *pktbuf, size_t bufsz);
void qc_set_stopwatch(qconnection_t *c, stopwatch_t *w);
int qc_recv(qconnection_t *c, void *buf, size_t len, tick_t rxtime);

// Client code
int qc_connect(qconnection_t *c, const char *server_name, const br_x509_class **validator, const qcrypto_params_t *params);

// Server code
typedef struct qconnect_request qconnect_request_t;
struct qconnect_request {
	tick_t rxtime;
	uint64_t destination;
	uint8_t source[QUIC_ADDRESS_SIZE];

	const uint8_t *random;

	const char *server_name;
	size_t name_len;

	br_ec_public_key key;
	const qcipher_class *cipher;
	uint64_t signatures;

	const void *raw;
	size_t raw_size;
};

#define QC_PARSE_ERROR -1
#define QC_WRONG_VERSION -2
#define QC_STATELESS_RETRY -3

int qc_get_destination(void *buf, size_t len, uint64_t *out);
int qc_decode_request(qconnect_request_t *h, void *buf, size_t len, tick_t rxtime, const qcrypto_params_t *params);
int qc_accept(qconnection_t *c, const qconnect_request_t *h, const qsigner_class *const *signer);

// By default we support the 5 ECDHE groups in TLS 1.3
// Priority is given to x22519 and secp256r1
#define TLS_DEFAULT_GROUPS "\x1D\x17\x18\x19\x1E"
