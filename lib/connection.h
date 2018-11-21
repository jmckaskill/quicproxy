#pragma once

#include "common.h"
#include "stream.h"
#include "cipher.h"
#include "packets.h"
#include "signature.h"


typedef int(*quic_send)(void *user, const void *buf, size_t len, tick_t *sent);

typedef struct qinterface qinterface_t;
struct qinterface {
	int(*send)(const qinterface_t **iface, const void *addr, const void *buf, size_t len, tick_t *sent);
	qstream_t*(*open)(const qinterface_t **iface, bool unidirectional);
	void(*close)(const qinterface_t **iface, qstream_t *s);
	void(*read)(const qinterface_t **iface, qstream_t *s);
	void(*change_peer_address)(const qinterface_t **iface, const void *addr);
};

typedef struct qtx_packet qtx_packet_t;
struct qtx_packet {
	uint64_t off;
	size_t len;
	qstream_t *stream;
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

struct qconnection {
	// caller interface
	const qinterface_t **iface;

	// send/recv
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
	int64_t rx_crypto_off;
	struct crypto_decoder rx_crypto;
	union {
		struct server_hello server_hello;
		struct verify verify;
		struct finished finished;
		qconnect_params_t extensions;
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
	const qsigner_class *const *signer;
	const char *server_name;
	const qconnect_params_t *params;

	// transcript digest
	const br_hash_class **msg_hash;
	br_sha256_context msg_sha256;
	br_sha384_context msg_sha384;

	// streams
	struct {
		uint64_t max;
		uint64_t next;
		qstream_t *first;
		qstream_t *last;
	} pending_streams[2];
	rbtree active_streams[4];
	uint32_t max_stream_data[4];
	uint64_t max_data;
};

int qc_init(qconnection_t *c, const qinterface_t **vt, br_prng_seeder seedfn, void *pktbuf, size_t bufsz);
int qc_recv(qconnection_t *c, const void *addr, void *buf, size_t len, tick_t rxtime);

void qc_add_stream(qconnection_t *c, qstream_t *s);
void qc_rm_stream(qconnection_t *c, qstream_t *s);
int qc_flush_stream(qconnection_t *c, qstream_t *s);

// Client code
int qc_connect(qconnection_t *c, const char *server_name, const br_x509_class **validator, const qconnect_params_t *params);

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

	qconnect_params_t client_params;
	const qconnect_params_t *server_params;

	const void *raw;
	size_t raw_size;
};

#define QC_PARSE_ERROR -1
#define QC_WRONG_VERSION -2
#define QC_STATELESS_RETRY -3

int qc_get_destination(void *buf, size_t len, uint64_t *out);
int qc_decode_request(qconnect_request_t *h, void *buf, size_t len, tick_t rxtime, const qconnect_params_t *params);
int qc_accept(qconnection_t *c, const qconnect_request_t *h, const qsigner_class *const *signer);

