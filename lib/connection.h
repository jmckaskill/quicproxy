#pragma once

#include "common.h"
#include "stream.h"
#include "cipher.h"
#include "handshake.h"
#include "signature.h"
#include <cutils/apc.h>


typedef int(*quic_send)(void *user, const void *buf, size_t len, tick_t *sent);

typedef struct qinterface qinterface_t;
struct qinterface {
	void(*disconnect)(const qinterface_t **iface, int error);
	int(*send)(const qinterface_t **iface, const void *addr, const void *buf, size_t len, tick_t *sent);
	qstream_t*(*open)(const qinterface_t **iface, bool unidirectional);
	void(*close)(const qinterface_t **iface, qstream_t *s);
	void(*read)(const qinterface_t **iface, qstream_t *s);
	void(*change_peer_address)(const qinterface_t **iface, const void *addr);
};

typedef struct qtx_packet qtx_packet_t;
struct qtx_packet {
	rbnode rb;
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
	bool handshake_complete;

	// crypto management
	qcipher_compat prot_tx;
	qcipher_compat prot_rx;
	uint8_t client_random[QUIC_RANDOM_SIZE];
	uint8_t server_random[QUIC_RANDOM_SIZE];
	uint8_t hs_secret[QUIC_MAX_HASH_SIZE];
	uint8_t hs_rx[QUIC_MAX_HASH_SIZE];
	uint8_t hs_tx[QUIC_MAX_HASH_SIZE];
	uint8_t finished_hash[QUIC_MAX_HASH_SIZE];
	uint8_t cert_msg_hash[QUIC_MAX_HASH_SIZE];
	br_hmac_drbg_context rand;
	struct crypto_decoder rx_crypto;
	const qconnect_params_t *params;

	// cipher
	const qcipher_class *cipher;

	// key group
	br_ec_private_key keys[QUIC_MAX_KEYSHARE];
	uint8_t key_data[QUIC_MAX_KEYSHARE][BR_EC_KBUF_PRIV_MAX_SIZE];

	// certificates
	const qsignature_class *signature;
	const br_x509_class **validator;
	const qsigner_class *const *signer;

	// transcript digest
	const br_hash_class **msg_hash;
	br_sha256_context msg_sha256;
	br_sha384_context msg_sha384;

	// streams
	qpacket_buffer_t pkts[3];
	size_t tx_stream_packets;
	struct {
		uint64_t max;
		uint64_t next;
		rbtree streams;
	} pending[2];
	rbtree tx_streams;
	rbtree rx_streams[4];
	uint32_t max_stream_data[4];
	uint64_t max_data;

	// timeout
	int retransmit_count;
	apc_t retransmit_timer;
	apc_t idle_timer;
	apc_t ack_timer;
	dispatcher_t *dispatcher;
	tickdiff_t rtt;
};

void qc_close(qconnection_t *c);
void qc_recv(qconnection_t *c, const void *addr, void *buf, size_t len, tick_t rxtime);
void qc_move(qconnection_t *c, dispatcher_t *d);

void qc_add_stream(qconnection_t *c, qstream_t *s);
void qc_rm_stream(qconnection_t *c, qstream_t *s);
void qc_flush_stream(qconnection_t *c, qstream_t *s);

// Client code
typedef struct qconnect_params qconnect_params_t;
struct qconnect_params {
	br_prng_seeder seeder;
	const char *server_name;
	const char *groups;
	const qcipher_class *const *ciphers;
	const qsignature_class *const *signatures;
	// these refer to the initial maximum data the remote is allowed to send us
	uint32_t stream_data_bidi_local; // for bidi streams initiated by us
	uint32_t stream_data_bidi_remote; // for bidi streams initiated by the remote
	uint32_t stream_data_uni; // for uni streams initiated by the remote
	// these refer to the initial maximum streams the remote is allowed to initiate
	uint32_t bidi_streams;
	uint32_t uni_streams;
	// the initial maximum of the total data sent to us
	uint32_t max_data;
	tickdiff_t idle_timeout;
	tickdiff_t ping_timeout;
	log_t *debug;
	log_t *keylog;
};
int qc_connect(qconnection_t *c, dispatcher_t *d, const qinterface_t **vt, const br_x509_class **x, const qconnect_params_t *p, qtx_packet_t *buf, size_t num);

// Server code
typedef struct qconnect_request qconnect_request_t;
struct qconnect_request {
	tick_t rxtime;
	uint8_t destination[QUIC_ADDRESS_SIZE];
	uint8_t source[QUIC_ADDRESS_SIZE];

	const uint8_t *client_random;

	const char *server_name;
	size_t name_len;

	br_ec_public_key key;
	const qcipher_class *cipher;
	uint64_t signatures;

	qconnect_params_t client_params;
	const qconnect_params_t *server_params;

	const void *chello;
	size_t chello_size;
};

int qc_get_destination(void *buf, size_t len, uint8_t *out);
int qc_decode_request(qconnect_request_t *h, void *buf, size_t len, tick_t rxtime, const qconnect_params_t *params);
int qc_accept(qconnection_t *c, dispatcher_t *d, const qinterface_t **vt, const qconnect_request_t *h, const qsigner_class *const *s, qtx_packet_t *buf, size_t num);

