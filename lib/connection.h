#pragma once

#include "common.h"
#include "stream.h"
#include "cipher.h"
#include "handshake.h"
#include "signature.h"
#include <cutils/apc.h>


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
	const br_x509_class**(*start_chain)(const qinterface_t **iface, const char *server_name);
};


struct qtx_packet {
	uint64_t off;
	rbnode rb;
	qstream_t *stream;
	tick_t sent;
	uint16_t len;
	uint16_t flags;
};

typedef struct qpacket_buffer qpacket_buffer_t;
struct qpacket_buffer {
	qtx_packet_t *sent;	// packets sent for retries
	size_t sent_len;	// number of packets in the send buffer
	uint64_t tx_next;   // next packet to send (highest sent + 1)
	uint64_t tx_oldest; // oldest packet still outstanding
	tick_t rx_largest;
	uint64_t rx_next;
	uint64_t rx_mask;
};

typedef struct qconnection_cfg qconnection_cfg_t;
struct qconnection_cfg {
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
	br_prng_seeder seeder;
	const char *groups;
	const qcipher_class *const *ciphers;
	const qsignature_class *const *signatures;
	log_t *debug;
	log_t *keylog;
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
	bool have_srtt;
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
	const qconnection_cfg_t *local_cfg;
	qconnection_cfg_t peer_cfg;

	// cipher
	const qcipher_class *cipher;

	// key group
	br_ec_private_key keys[QUIC_MAX_KEYSHARE];
	uint8_t key_data[QUIC_MAX_KEYSHARE][BR_EC_KBUF_PRIV_MAX_SIZE];

	// certificates
	const qsignature_class *signature;
	const qsigner_class *const *signer;
	const char *server_name;

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
	uint64_t tx_max_data;
	uint64_t data_sent;
	uint64_t rx_max_data;
	uint64_t data_received;

	// timeout
	int rx_timer_count;
	apc_t rx_timer;
	apc_t tx_timer;
	apc_t idle_timer;
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
int qc_connect(qconnection_t *c, dispatcher_t *d, const qinterface_t **vt, const char *server_name, const qconnection_cfg_t *p, void *pktbuf, size_t sz);

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

	qconnection_cfg_t client_cfg;
	const qconnection_cfg_t *server_cfg;

	const void *chello;
	size_t chello_size;
};

int qc_get_destination(void *buf, size_t len, uint8_t *out);
int qc_decode_request(qconnect_request_t *h, void *buf, size_t len, tick_t rxtime, const qconnection_cfg_t *params);
int qc_accept(qconnection_t *c, dispatcher_t *d, const qinterface_t **vt, const qconnect_request_t *h, const qsigner_class *const *s, void *pktbuf, size_t sz);

