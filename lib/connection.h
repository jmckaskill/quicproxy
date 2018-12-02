#pragma once

#include "common.h"
#include "stream.h"
#include "cipher.h"
#include "handshake.h"
#include "signature.h"
#include <cutils/socket.h>
#include <cutils/apc.h>


typedef struct qinterface qinterface_t;
struct qinterface {
	void(*close)(const qinterface_t **iface);
	void(*shutdown)(const qinterface_t **iface, int error);
	int(*send)(const qinterface_t **iface, const void *buf, size_t len, const struct sockaddr *sa, socklen_t salen, tick_t *sent);
	void(*change_peer_address)(const qinterface_t **iface, const struct sockaddr *sa, socklen_t len);
	qstream_t*(*new_stream)(const qinterface_t **iface, bool unidirectional);
	void(*free_stream)(const qinterface_t **iface, qstream_t *s);
	void(*data_received)(const qinterface_t **iface, qstream_t *s);
	void(*data_sent)(const qinterface_t **iface, qstream_t *s);
	const br_x509_class**(*start_chain)(const qinterface_t **iface, const char *server_name);
};


typedef struct qconnection_cfg qconnection_cfg_t;
struct qconnection_cfg {
	// these refer to the initial maximum data the remote is allowed to send us
	uint32_t stream_data_bidi_local; // for bidi streams initiated by us
	uint32_t stream_data_bidi_remote; // for bidi streams initiated by the remote
	uint32_t stream_data_uni; // for uni streams initiated by the remote
	// these indicate the maximum number of concurrent streams allowed
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

void qc_close(qconnection_t *c);
void qc_shutdown(qconnection_t *c, int error);
void qc_recv(qconnection_t *c, void *buf, size_t len, const struct sockaddr *sa, socklen_t salen, tick_t rxtime);
void qc_move(qconnection_t *c, dispatcher_t *d);

void qc_flush(qconnection_t *c, qstream_t *s);

// Client code
int qc_connect(qconnection_t *c, size_t csz, dispatcher_t *d, const qinterface_t **vt, const char *server_name, const qconnection_cfg_t *p);

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
int qc_accept(qconnection_t *c, size_t csz, dispatcher_t *d, const qinterface_t **vt, const qconnect_request_t *h, const qsigner_class *const *s);

