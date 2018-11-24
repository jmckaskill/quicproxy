#pragma once

#include "common.h"
#include "stream.h"
#include "cipher.h"
#include "handshake.h"
#include "signature.h"
#include <cutils/stopwatch.h>


typedef int(*quic_send)(void *user, const void *buf, size_t len, qmicrosecs_t *sent);

typedef struct qinterface qinterface_t;
struct qinterface {
	int(*send)(const qinterface_t **iface, const void *addr, size_t addrlen, const void *buf, size_t len, qmicrosecs_t *sent);
	qstream_t*(*open)(const qinterface_t **iface, bool unidirectional);
	void(*close)(const qinterface_t **iface, qstream_t *s);
	void(*read)(const qinterface_t **iface, qstream_t *s);
	void(*change_peer_address)(const qinterface_t **iface, const void *addr, size_t len);
};

typedef struct qtx_packet qtx_packet_t;
struct qtx_packet {
	rbnode rb;
	uint64_t off;
	size_t len;
	qstream_t *stream;
	qmicrosecs_t sent;
};

typedef struct qpacket_buffer qpacket_buffer_t;
struct qpacket_buffer {
	qtx_packet_t *sent;	// packets sent for retries
	size_t sent_len;	// number of packets in the send buffer
	uint64_t received;	// receive bitset - one bit per packet
	uint64_t rx_next;   // next packet to receive (highest received + 1)
	uint64_t tx_next;   // next packet to send (highest sent + 1)
	uint64_t tx_oldest; // oldest packet still outstanding
};

struct qconnection {
	// caller interface
	const qinterface_t **iface;

	// send/recv
	uint8_t local_id[QUIC_ADDRESS_SIZE];
	uint8_t peer_id[QUIC_ADDRESS_SIZE];
	bool is_client;
	bool have_prot_keys;
	bool peer_verified;
	bool finished_sent;
	bool handshake_acknowledged;

	// crypto management
	qcipher_compat prot_tx;
	qcipher_compat prot_rx;
	uint8_t client_random[QUIC_RANDOM_SIZE];
	uint8_t server_random[QUIC_RANDOM_SIZE];
	uint8_t hs_secret[QUIC_MAX_HASH_SIZE];
	uint8_t hs_rx[QUIC_MAX_HASH_SIZE];
	uint8_t hs_tx[QUIC_MAX_HASH_SIZE];
	uint8_t client_finished[QUIC_MAX_HASH_SIZE];
	br_hmac_drbg_context rand;
	struct crypto_decoder rx_crypto;

	// logging
	log_t *debug;
	log_t *keylog;

	// cipher
	const qcipher_class *cipher;

	// key group
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
	qpacket_buffer_t pkts[3];
	struct {
		uint64_t max;
		uint64_t next;
		qstream_t *first;
		qstream_t *last;
	} pending_streams[2];
	qstream_t *tx_streams;
	rbtree sorted_streams[4];
	uint32_t max_stream_data[4];
	uint64_t max_data;

	// timeout
	qmicrosecs_t retransmit_timer;
	qmicrosecs_t idle_timer;
	qmicrosecs_t rtt;


};

int qc_init(qconnection_t *c, const qinterface_t **vt, br_prng_seeder seedfn, void *pktbuf, size_t bufsz);
int qc_recv(qconnection_t *c, const void *addr, size_t addrlen, void *buf, size_t len, qmicrosecs_t rxtime, qmicrosecs_t *ptimeout);
int qc_timeout(qconnection_t *c, qmicrosecs_t now, qmicrosecs_t *ptimeout);

void qc_add_stream(qconnection_t *c, qstream_t *s);
void qc_rm_stream(qconnection_t *c, qstream_t *s);
int qc_flush_stream(qconnection_t *c, qstream_t *s);

// Client code
int qc_connect(qconnection_t *c, const char *server_name, const br_x509_class **validator, const qconnect_params_t *params, qmicrosecs_t *ptimeout);

// Server code
typedef struct qconnect_request qconnect_request_t;
struct qconnect_request {
	qmicrosecs_t rxtime;
	uint8_t destination[QUIC_ADDRESS_SIZE];
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


int qc_get_destination(void *buf, size_t len, uint8_t *out);
int qc_decode_request(qconnect_request_t *h, void *buf, size_t len, qmicrosecs_t rxtime, const qconnect_params_t *params);
int qc_accept(qconnection_t *c, const qconnect_request_t *h, const qsigner_class *const *signer, qmicrosecs_t *ptimeout);

