#pragma once
#include "common.h"
#include "stream.h"
#include "connection.h"
#include "cipher.h"
#include "kdf.h"
#include "signature.h"
#include <cutils/endian.h>
#include <cutils/log.h>
#include <inttypes.h>
#include <limits.h>

// packet flags
#define QPKT_SEND          (1 << 0)
#define QPKT_PATH_CHALLENGE	(1 << 1)
#define QPKT_PATH_RESPONSE	(1 << 2)
#define QPKT_FIN				(1 << 3)
#define QPKT_RST				(1 << 4)
#define QPKT_STOP			(1 << 5)
#define QPKT_STREAM_DATA		(1 << 6)
#define QPKT_MAX_DATA		(1 << 7)
#define QPKT_MAX_ID_UNI		(1 << 8)
#define QPKT_MAX_ID_BIDI		(1 << 9)
#define QPKT_NEW_TOKEN		(1 << 10)
#define QPKT_CWND            (1 << 11)
#define QPKT_NEW_ID			(1 << 13)
#define QPKT_RETIRE_ID		(1 << 14)

// stream flags
#define QS_TX_COMPLETE (1 << 0)
#define QS_RX_COMPLETE (1 << 1)
#define QS_TX_FIN      (1 << 4)
#define QS_TX_FIN_SEND (1 << 5)
#define QS_RX_FIN_ACK  (1 << 6)
#define QS_RX_FIN      (1 << 7)
#define QS_TX_RST      (1 << 8)
#define QS_TX_RST_SEND (1 << 9)
#define QS_RX_RST_ACK  (1 << 10)
#define QS_RX_RST      (1 << 11)
#define QS_TX_STOP     (1 << 12)
#define QS_TX_STOP_SEND (1 << 13)
#define QS_RX_STOP_ACK (1 << 14)
#define QS_RX_STOP     (1 << 15)
#define QS_TX_CONTROL  (1 << 16)
#define QS_TX_DATA     (1 << 17)
#define QS_STARTED      (1 << 18)
#define QS_NOT_STARTED      (1 << 19)

// connection flags
#define QC_IS_SERVER           (1 << 0)
#define QC_INIT_COMPLETE       (1 << 1)
#define QC_HS_RECEIVED         (1 << 2)
#define QC_HS_COMPLETE         (1 << 3)
#define QC_FIN_ACKNOWLEDGED    (1 << 4)
#define QC_MIGRATING           (1 << 5)
#define QC_CLOSING             (1 << 6)
#define QC_DRAINING            (1 << 7)
#define QC_PATH_CHALLENGE_SEND (1 << 8)
#define QC_HAVE_PATH_CHALLENGE (1 << 9)
#define QC_PATH_RESPONSE_SEND  (1 << 10)

#define QRST_STOPPING 0
#define QRX_STREAM_MAX UINT64_C(0x4000000000000000)

#define VARINT_16 UINT16_C(0x4000)
#define VARINT_32 UINT32_C(0x80000000)
#define VARINT_64 UINT64_C(0xC000000000000000)

// packet types
#define LONG_HEADER_FLAG 0x80
#define INITIAL_PACKET 0xFF
#define RETRY_PACKET 0xFE
#define HANDSHAKE_PACKET 0xFD
#define PROTECTED_PACKET 0xFC
#define SHORT_PACKET 0x30
#define SHORT_PACKET_MASK 0xB8

// frame types
#define PADDING 0
#define RST_STREAM 1
#define CONNECTION_CLOSE 2
#define APPLICATION_CLOSE 3
#define MAX_DATA 4
#define MAX_STREAM_DATA 5
#define MAX_STREAM_ID 6
#define PING 7
#define BLOCKED 8
#define STREAM_BLOCKED 9
#define STREAM_ID_BLOCKED 0x0A
#define NEW_CONNECTION_ID 0x0B
#define STOP_SENDING 0x0C
#define RETIRE_CONNECTION_ID 0x0D
#define PATH_CHALLENGE 0x0E
#define PATH_RESPONSE 0x0F
#define STREAM 0x10
#define STREAM_OFF_FLAG 4
#define STREAM_LEN_FLAG 2
#define STREAM_FIN_FLAG 1
#define STREAM_MASK 0xF8
#define CRYPTO 0x18
#define NEW_TOKEN 0x19
#define ACK 0x1A
#define ACK_MASK 0xFE
#define ACK_ECN_FLAG 1

#define STREAM_CLIENT 0
#define STREAM_SERVER 1
#define STREAM_SERVER_MASK 1
#define STREAM_BIDI 0
#define STREAM_UNI 2
#define STREAM_UNI_MASK 2

#define PENDING_BIDI 0
#define PENDING_UNI 1

#define PATH_CHALLENGE_IV 16
#define RETRY_TOKEN_IV 32
#define RETRY_ID_IV 512

#define ARRAYSZ(A) (sizeof(A) / sizeof((A)[0]))
#define ALIGN_DOWN(type, u, sz) ((u) &~ ((type)(sz)-1))
#define ALIGN_UP(type, u, sz) ALIGN_DOWN(type, (u) + (sz) - 1, (sz))
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

#define INITIAL_WINDOW MIN(10*DEFAULT_PACKET_SIZE, MAX(2*DEFAULT_PACKET_SIZE, 14600))
#define MIN_WINDOW (2*DEFAULT_PACKET_SIZE)

enum qcrypto_level {
	QC_INITIAL,
	QC_HANDSHAKE,
	QC_PROTECTED,
};

enum request_crypto_state {
	REQUEST_START,
	CHELLO_HEADER,
	CHELLO_LEGACY_VERSION,
	CHELLO_RANDOM,
	CHELLO_LEGACY_SESSION,
	CHELLO_CIPHER_LIST_SIZE,
	CHELLO_CIPHER,
	CHELLO_CIPHER_LIST,
	CHELLO_COMPRESSION,
	CHELLO_EXT_LIST_SIZE,
	CHELLO_EXT_HEADER,
	CHELLO_EXT,
	CHELLO_NAME_LIST_SIZE,
	CHELLO_NAME_HEADER,
	CHELLO_NAME,
	CHELLO_NAME_IGNORE,
	CHELLO_VERSIONS_LIST_SIZE,
	CHELLO_VERSION,
	CHELLO_KEY_LIST_SIZE,
	CHELLO_KEY_GROUP,
	CHELLO_KEY_SIZE,
	CHELLO_KEY_TYPE,
	CHELLO_KEY_DATA,
	CHELLO_KEY,
	CHELLO_KEY_IGNORE,
	CHELLO_KEY_LIST,
	CHELLO_ALGORITHMS_LIST_SIZE,
	CHELLO_ALGORITHM,
	CHELLO_TP_INITIAL_VERSION,
	CHELLO_TP_LIST_SIZE,
	CHELLO_TP_HEADER,
	CHELLO_TP_stream_data_bidi_local,
	CHELLO_TP_stream_data_bidi_remote,
	CHELLO_TP_stream_data_uni,
	CHELLO_TP_max_data,
	CHELLO_TP_bidi_streams,
	CHELLO_TP_uni_streams,
	CHELLO_TP_idle_timeout,
	CHELLO_TP_max_packet_size,
	CHELLO_TP_ack_delay_exponent,
	CHELLO_TP_max_ack_delay,
	CHELLO_TP,
	CHELLO,
};

enum handshake_crypto_state {
	CLIENT_START,
	SHELLO_HEADER,
	SHELLO_LEGACY_VERSION,
	SHELLO_RANDOM,
	SHELLO_LEGACY_SESSION,
	SHELLO_CIPHER,
	SHELLO_COMPRESSION,
	SHELLO_EXT_LIST_SIZE,
	SHELLO_EXT_HEADER,
	SHELLO_SUPPORTED_VERSION,
	SHELLO_KEY_GROUP,
	SHELLO_KEY_SIZE,
	SHELLO_KEY_TYPE,
	SHELLO_KEY_DATA,
	SHELLO_FINISH_EXTENSION,
	SHELLO,

	EXTENSIONS_LEVEL,
	EXTENSIONS_HEADER,
	EXTENSIONS_LIST_SIZE,
	EXTENSIONS_EXT_HEADER,
	EXTENSIONS_EXT,
	EXTENSIONS,
	EXTENSIONS_SUPPORTED_VERSIONS,
	EXTENSIONS_SUPPORTED_VERSIONS_SIZE,
	EXTENSIONS_NEGOTIATED_VERSION,
	EXTENSIONS_TP_LIST_SIZE,
	EXTENSIONS_TP_KEY,
	EXTENSIONS_TP,
	EXTENSIONS_TP_stream_data_bidi_local,
	EXTENSIONS_TP_stream_data_bidi_remote,
	EXTENSIONS_TP_stream_data_uni,
	EXTENSIONS_TP_bidi_streams,
	EXTENSIONS_TP_uni_streams,
	EXTENSIONS_TP_max_data,
	EXTENSIONS_TP_idle_timeout,
	EXTENSIONS_TP_max_packet_size,
	EXTENSIONS_TP_ack_delay_exponent,
	EXTENSIONS_TP_max_ack_delay,
	EXTENSIONS_TP_original_connection_id,

	CERTIFICATE_HEADER,
	CERTIFICATE_CONTEXT,
	CERTIFICATE_LIST_SIZE,
	CERTIFICATE_DATA_SIZE,
	CERTIFICATE_DATA,
	CERTIFICATE_EXT_SIZE,
	CERTIFICATE_EXT,
	CERTIFICATE,

	VERIFY_HEADER,
	VERIFY_ALGORITHM,
	VERIFY_SIG_SIZE,
	VERIFY_SIG_DATA,
	VERIFY,

	ACCEPT_START,
	FINISHED_HEADER,
	FINISHED,
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
	uint64_t tx_largest_acked;
};

struct connection {
	// caller interface
	const qinterface_t **iface;
	uint16_t flags;

	// send/recv
	uint8_t peer_len;
	uint8_t peer_id[QUIC_MAX_ADDRESS_SIZE];
	uint32_t version;
	struct sockaddr_storage addr;
	socklen_t addr_len;
	uint8_t is_server;
	int close_errnum;

	qcipher_compat prot_tx;
	qcipher_compat prot_rx;
	qpacket_buffer_t prot_pkts;
	uint8_t client_random[QUIC_RANDOM_SIZE];
	uint8_t tx_finished[QUIC_MAX_HASH_SIZE];

	const qconnection_cfg_t *local_cfg;
	qconnection_cfg_t peer_cfg;

	// streams
	size_t retransmit_packets;
	rbtree rx_streams[4];
	struct qstream_list *uni_pending;
	struct qstream_list *bidi_pending;
	struct qstream_list *data_pending;
	struct qstream_list *ctrl_pending;
	uint64_t next_id[4];
	uint64_t max_id[4];

	// connection flow control
	uint64_t tx_data_max;
	uint64_t tx_data;
	uint64_t rx_data_max;
	uint64_t rx_data;

	// congestion window
	uint64_t congestion_window;
	uint64_t bytes_in_flight;
	uint64_t after_recovery;
	uint64_t slow_start_threshold;
	uint64_t ecn_ce_counter;

	// timeout
	int rx_timer_count;
	apc_t rx_timer;
	apc_t ack_timer;
	apc_t idle_timer;
	apc_t flush_apc;
	dispatcher_t *dispatcher;
	uint64_t rto_next;
	tickdiff_t min_rtt;
	tickdiff_t srtt;
	tickdiff_t rttvar;
};

struct crypto_state {
	int level;
	uint32_t next;
	int state;
	uint32_t end;
	uint32_t stack[6];
	uint32_t have_bytes;
	uint8_t buf[7];
	uint8_t bufsz;
	uint8_t depth;

	const br_hash_class **msgs;
	br_sha256_context msg_sha256;
	br_sha384_context msg_sha384;
};

struct handshake {
	struct connection c;
	struct crypto_state crypto;

	uint64_t orig_server_id;
	qpacket_buffer_t pkts[2];
	uint8_t hs_secret[QUIC_MAX_HASH_SIZE];
	uint8_t hs_rx[QUIC_MAX_HASH_SIZE];
	uint8_t hs_tx[QUIC_MAX_HASH_SIZE];
	uint8_t server_random[QUIC_RANDOM_SIZE];
	uint8_t rx_finished[QUIC_MAX_HASH_SIZE];
	uint8_t msg_hash[QUIC_MAX_HASH_SIZE];
	
	const qcipher_class *cipher;

	uint8_t *conn_buf_end;
};

struct client_handshake {
	struct handshake h;
	qtx_packet_t init_pkts[16];
	qtx_packet_t hs_pkts[8];
	uint8_t token_size;
	uint8_t token[255];

	const br_x509_class **x509;
	const char *server_name;

	union {
		struct {
			bool have_tls_version;
			br_ec_public_key k;
			uint8_t key_data[BR_EC_KBUF_PUB_MAX_SIZE];
		} sh;

		struct {
			uint64_t orig_server_id;
		} ee;

		struct {
			uint16_t algorithm;
			size_t len;
			uint8_t sig[QUIC_MAX_SIG_SIZE];
		} v;

		struct {
			size_t len;
			uint8_t fin[QUIC_MAX_HASH_SIZE];
		} f;
	} u;
	uint32_t initial_version;

	size_t key_num;
	uint8_t keys[1];
};

struct server_handshake {
	struct handshake h;
	qtx_packet_t init_pkts[3];
	qtx_packet_t hs_pkts[3];
	br_ec_private_key sk;
	uint8_t key_data[BR_EC_KBUF_PRIV_MAX_SIZE];
	uint8_t cert_msg_hash[QUIC_MAX_HASH_SIZE];
	uint8_t server_random[QUIC_RANDOM_SIZE];
	const qsignature_class *signature;
	const qsigner_class *const *signer;
	uint8_t server_id[DEFAULT_SERVER_ID_LEN];
};

static inline uint8_t q_encode_id_len(uint8_t len) {
	return len ? (len - 3) : 0;
}
static inline uint8_t q_decode_id_len(uint8_t val) {
	return val ? (val + 3) : 0;
}
uint8_t *q_encode_varint(uint8_t *p, uint64_t val);
int q_decode_varint(qslice_t *s, uint64_t *pval);
uint8_t *q_encode_packet_number(uint8_t *p, uint64_t base, uint64_t val);
uint8_t *q_decode_packet_number(uint8_t *p, uint64_t base, uint64_t *pval);
uint64_t q_generate_local_id(const qconnection_cfg_t *cfg, const br_prng_class **r);

// Crypto

int q_decode_handshake_crypto(struct connection *c, enum qcrypto_level level, qslice_t *fd, tick_t rxtime);
int q_decode_request_crypto(qconnect_request_t *req, qslice_t *fd);
const br_hash_class **init_message_hash(struct handshake *h);
void init_protected_keys(struct handshake *h, const uint8_t *msg_hash);



uint8_t *q_encode_finished(struct connection *c, uint8_t *p);

// Packet sending

#define SEND_FORCE 1
#define SEND_PING 2
void q_send_handshake_close(struct connection *c);
void q_send_close(struct connection *c);
qtx_packet_t *q_send_packet(struct connection *c, tick_t now, uint8_t flags);
uint8_t *q_encode_ack(qpacket_buffer_t *pkts, uint8_t *p, tick_t now, unsigned exp);

qtx_packet_t *q_send_client_hello(struct client_handshake *ch, const br_prng_class **rand, tick_t now);
int q_send_server_hello(struct server_handshake *sh, const br_prng_class **rand, const br_ec_public_key *pk, tick_t now);

// Streams
void q_setup_local_stream(struct connection *c, qstream_t *s, uint64_t id);
void q_setup_remote_stream(struct connection *c, qstream_t *s, uint64_t id);
int q_recv_stream(struct connection *c, qstream_t *s, bool fin, uint64_t off, const void *p, size_t sz);
int q_recv_max_stream(struct connection *c, qstream_t *s, uint64_t off);
int q_recv_stop(struct connection *c, qstream_t *s, int errnum);
int q_recv_reset(struct connection *c, qstream_t *s, int errnum, uint64_t off);
uint8_t *q_encode_stream(struct connection *c, qstream_t *s, uint8_t *p, uint8_t *e, qtx_packet_t *pkt, bool pad);
void q_commit_stream(struct connection *c, qstream_t *s, qtx_packet_t *pkt);
void q_ack_stream(struct connection *c, qstream_t *s, qtx_packet_t *pkt);
void q_lost_stream(struct connection *c, qstream_t *s, qtx_packet_t *pkt);

// Scheduler

void q_update_scheduler_from_cfg(struct connection *c);
void q_free_streams(struct connection *c);

int q_decode_stream(struct connection *c, uint8_t hdr, qslice_t *s);
int q_decode_reset(struct connection *c, qslice_t *s);
int q_decode_stop(struct connection *c, qslice_t *p);
int q_decode_stream_data(struct connection *c, qslice_t *s);
int q_decode_max_data(struct connection *c, qslice_t *s);
int q_decode_max_id(struct connection *c, qslice_t *p);
int q_decode_blocked(struct connection *c, qslice_t *p);
int q_decode_stream_blocked(struct connection *c, qslice_t *p);
int q_decode_id_blocked(struct connection *c, qslice_t *p);

uint8_t *q_encode_scheduler(struct connection *c, uint8_t *p, qtx_packet_t *pkt);
void q_commit_scheduler(struct connection *c, const qtx_packet_t *pkt);

void q_remove_stream(struct connection *c, qstream_t *s);

// Shutdown

void q_shutdown_from_idle(struct connection *c);
void q_shutdown_from_library(struct connection *c, int errnum);
int q_decode_close(struct connection *c, uint8_t hdr, qslice_t *s, tick_t now);
uint8_t *q_encode_close(struct connection *c, uint8_t *p, uint8_t *e, bool pad);

// Timers

void q_fast_async_ack(struct connection *c, tick_t now);
void q_async_ack(struct connection *c, tick_t now);

void q_reset_rx_timer(struct connection *c, tick_t now);
void q_async_send_data(struct connection *c);
void q_reset_idle_timer(struct connection *c, tick_t now);

void q_start_migration(struct connection *c, tick_t now);
void q_start_handshake_timers(struct handshake *h, tick_t now);
void q_start_runtime_timers(struct handshake *h, tick_t now);
void q_start_shutdown(struct connection *c);

// Congestion
void q_reset_cwnd(struct connection *c, uint64_t first_after_reset);
size_t q_cwnd_sent(struct connection *c, const qtx_packet_t *pkt);
void q_ack_cwnd(struct connection *c, uint64_t pktnum, const qtx_packet_t *pkt);
void q_cwnd_ecn(struct connection *c, uint64_t pktnum, uint64_t ecn_ce);
void q_lost_cwnd(struct connection *c, const qtx_packet_t *pkt);
void q_cwnd_largest_lost(struct connection *c, uint64_t pktnum);
bool q_cwnd_allow(struct connection *c);

// Retry
size_t q_sockaddr_aad(uint8_t *o, const struct sockaddr *sa, socklen_t salen);
size_t q_encode_retry(qconnect_request_t *req, void *buf, size_t bufsz);
bool q_is_retry_valid(qconnect_request_t *req, const uint8_t *data, size_t len);
void q_process_retry(struct client_handshake *ch, uint8_t scil, const uint8_t *source, qslice_t s, tick_t now);

// Version negotiation
size_t q_encode_version(qconnect_request_t *req, void *buf, size_t bufsz);
void q_process_version(struct client_handshake *ch, qslice_t s, tick_t now);

// Migration
int q_update_address(struct connection *c, uint64_t pktnum, const struct sockaddr *sa, socklen_t salen, tick_t rxtime);
int q_decode_path_challenge(struct connection *c, qslice_t *p);
int q_decode_path_response(struct connection *c, qslice_t *p);
int q_decode_new_id(struct connection *c, qslice_t *p);
int q_decode_retire_id(struct connection *c, qslice_t *p);
int q_decode_new_token(struct connection *c, qslice_t *p);
void q_ack_path_response(struct connection *c);
void q_lost_path_challenge(struct connection *c);
uint8_t *q_encode_migration(struct connection *c, uint8_t *p, qtx_packet_t *pkt);
void q_commit_migration(struct connection *c, const qtx_packet_t *pkt);

static inline uint64_t q_encode_ack_delay(tickdiff_t delay, unsigned exp) {
	return delay >> (exp ? exp : QUIC_ACK_DELAY_SHIFT);
}

static inline tickdiff_t q_decode_ack_delay(uint64_t raw, unsigned exp) {
	return (tickdiff_t)(raw << (exp ? exp : QUIC_ACK_DELAY_SHIFT));
}
