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
	void(*close)(const qinterface_t **iface);
	void(*shutdown)(const qinterface_t **iface, int error);
	int(*send)(const qinterface_t **iface, const void *addr, const void *buf, size_t len, tick_t *sent);
	void(*change_peer_address)(const qinterface_t **iface, const void *addr);
	qstream_t*(*new_stream)(const qinterface_t **iface, bool unidirectional);
	void(*free_stream)(const qinterface_t **iface, qstream_t *s);
	void(*data_received)(const qinterface_t **iface, qstream_t *s);
	void(*data_sent)(const qinterface_t **iface, qstream_t *s);
};

#define QTX_PKT_PATH_CHALLENGE	0x0001
#define QTX_PKT_PATH_RESPONSE	0x0002
#define QTX_PKT_ACK				0x0004
#define QTX_PKT_FIN				0x0008
#define QTX_PKT_RST				0x0010
#define QTX_PKT_MAX_STREAM_DATA 0x0020
#define QTX_PKT_MAX_DATA		0x0040
#define QTX_PKT_MAX_ID_UNI		0x0080
#define QTX_PKT_MAX_ID_BIDI		0x0100
#define QTX_PKT_NEW_TOKEN		0x0200
#define QTX_PKT_RETRANSMIT		0x0400
#define QTX_PKT_CLOSE			0x0800
#define QTX_PKT_NEW_ID			0x1000
#define QTX_PKT_RETIRE_ID		0x2000
#define QTX_PKT_STOP_SENDING	0x4000
#define QTX_PKT_CRYPTO			0x8000

typedef struct qtx_packet qtx_packet_t;
struct qtx_packet {
	uint64_t off;
	rbnode rb;
	qstream_t *stream;
	tick_t sent;
	uint16_t len;
	uint16_t flags;
};

typedef struct qrx_bitset qrx_bitset_t;
struct qrx_bitset {
	uint64_t next;
	uint64_t mask;
};

typedef struct qpacket_buffer qpacket_buffer_t;
struct qpacket_buffer {
	qtx_packet_t *sent;	// packets sent for retries
	size_t sent_len;	// number of packets in the send buffer
	uint64_t tx_next;   // next packet to send (highest sent + 1)
	uint64_t tx_oldest; // oldest packet still outstanding
	qrx_bitset_t rx;
	tick_t rx_largest;
};

typedef struct qtransport_params qtransport_params_t;
struct qtransport_params {
	// these refer to the initial maximum data the remote is allowed to send us
	uint32_t stream_data_bidi_local; // for bidi streams initiated by us
	uint32_t stream_data_bidi_remote; // for bidi streams initiated by the remote
	uint32_t stream_data_uni; // for uni streams initiated by the remote
	// these refer to the initial maximum streams the remote is allowed to initiate
	uint16_t bidi_streams;
	uint16_t uni_streams;
	// the initial maximum of the total data sent to us
	uint32_t max_data;
	tickdiff_t idle_timeout;
	tickdiff_t ping_timeout;
	tickdiff_t max_ack_delay;
	uint8_t ack_delay_exponent;
	uint16_t max_packet_size;
	bool disable_migration;
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
	bool closing;
	bool draining;
	bool hashed_hello;
	int close_errnum;

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
	qtransport_params_t peer_transport;

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
	size_t retransmit_packets;
	rbtree rx_streams[4];
	uint64_t next_stream_id[4];
	uint64_t max_stream_id[4];
	rbtree pending_streams[2];
	rbtree tx_streams;

	// timeout
	int retransmit_count;
	apc_t rx_timer; // used for timeouts for when expect replies (crypto, TLP & RTO)
	apc_t tx_timer; // used for delaying transmits for coalescing (ping, acks & send new streams)
	apc_t idle_timer; // used for detecting an idle link
	dispatcher_t *dispatcher;
	uint64_t retransmit_pktnum;
	tickdiff_t min_rtt;
	tickdiff_t srtt;
	tickdiff_t rttvar;
};

void qc_close(qconnection_t *c);
void qc_shutdown(qconnection_t *c, int error);
void qc_recv(qconnection_t *c, const void *addr, void *buf, size_t len, tick_t rxtime);
void qc_move(qconnection_t *c, dispatcher_t *d);

void qc_flush(qconnection_t *c, qstream_t *s);

// Client code
typedef struct qconnect_params qconnect_params_t;
struct qconnect_params {
	br_prng_seeder seeder;
	const char *server_name;
	const char *groups;
	const qcipher_class *const *ciphers;
	const qsignature_class *const *signatures;
	qtransport_params_t transport;
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

	qtransport_params_t client_transport;
	const qconnect_params_t *params;

	const void *chello;
	size_t chello_size;
};

int qc_get_destination(void *buf, size_t len, uint8_t *out);
int qc_decode_request(qconnect_request_t *h, void *buf, size_t len, tick_t rxtime, const qconnect_params_t *params);
int qc_accept(qconnection_t *c, dispatcher_t *d, const qinterface_t **vt, const qconnect_request_t *h, const qsigner_class *const *s, qtx_packet_t *buf, size_t num);

