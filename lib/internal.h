#pragma once
#include "common.h"
#include "stream.h"
#include "connection.h"
#include "handshake.h"
#include "cipher.h"
#include "kdf.h"
#include "signature.h"
#include <cutils/endian.h>
#include <cutils/log.h>
#include <inttypes.h>

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
#define QPKT_CLOSE			(1 << 12)
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

enum decoder_state {
	SHELLO_START,
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
	SHELLO_FINISH,

	EXTENSIONS_LEVEL,
	EXTENSIONS_HEADER,
	EXTENSIONS_LIST_SIZE,
	EXTENSIONS_EXT_HEADER,
	EXTENSIONS_FINISH_EXTENSION,
	EXTENSIONS_FINISH,
	EXTENSIONS_SUPPORTED_VERSIONS,
	EXTENSIONS_SUPPORTED_VERSIONS_SIZE,
	EXTENSIONS_NEGOTIATED_VERSION,
	EXTENSIONS_TP_LIST_SIZE,
	EXTENSIONS_TP_KEY,
	EXTENSIONS_TP_FINISH,
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

	CERTIFICATES_HEADER,
	CERTIFICATES_CONTEXT,
	CERTIFICATES_LIST_SIZE,
	CERTIFICATES_DATA_SIZE,
	CERTIFICATES_DATA,
	CERTIFICATES_EXT_SIZE,
	CERTIFICATES_EXT,
	CERTIFICATES_FINISH,

	VERIFY_START,
	VERIFY_HEADER,
	VERIFY_ALGORITHM,
	VERIFY_SIG_SIZE,
	VERIFY_SIG_DATA,
	VERIFY_FINISH,

	FINISHED_START,
	FINISHED_HEADER,
	FINISHED_DATA,
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

struct connection {
	// caller interface
	const qinterface_t **iface;

	// send/recv
	uint8_t local_id[QUIC_ADDRESS_SIZE];
	uint8_t peer_id[QUIC_ADDRESS_SIZE];
	uint32_t version;
	struct sockaddr_storage addr;
	socklen_t addr_len;
	bool is_client;
	bool have_prot_keys;
	bool peer_verified;
	bool path_validated;
	bool challenge_sent;
	bool handshake_complete;
	bool closing;
	bool close_sent;
	bool draining;
	bool have_path_response;
	bool path_response_sent;
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

struct handshake {
	struct connection c;
	int level;
	uint32_t next;
	enum decoder_state state;
	uint32_t end;
	uint32_t stack[4];
	uint32_t have_bytes;
	uint8_t buf[3];
	uint8_t bufsz;
	uint8_t depth;

	br_hmac_drbg_context rand;
	qpacket_buffer_t pkts[2];
	uint8_t hs_secret[QUIC_MAX_HASH_SIZE];
	uint8_t hs_rx[QUIC_MAX_HASH_SIZE];
	uint8_t hs_tx[QUIC_MAX_HASH_SIZE];
	uint8_t server_random[QUIC_RANDOM_SIZE];
	uint8_t rx_finished[QUIC_MAX_HASH_SIZE];
	uint8_t msg_hash[QUIC_MAX_HASH_SIZE];
	uint8_t original_destination[QUIC_ADDRESS_SIZE];

	const br_hash_class **msgs;
	br_sha256_context msg_sha256;
	br_sha384_context msg_sha384;

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
			uint16_t tls_version;
			br_ec_public_key k;
			uint8_t key_data[BR_EC_KBUF_PUB_MAX_SIZE];
		} sh;

		struct {
			uint8_t orig_dest[QUIC_ADDRESS_SIZE];
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
	bool hashed_hello;

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
};

// Packet sending

#define SEND_FORCE 1
#define SEND_PING 2
qtx_packet_t *q_send_packet(struct connection *c, tick_t now, uint8_t flags);
uint8_t *q_encode_ack(qpacket_buffer_t *pkts, uint8_t *p, tick_t now, unsigned exp);

// Streams
void q_setup_local_stream(struct connection *c, qstream_t *s, uint64_t id);
void q_setup_remote_stream(struct connection *c, qstream_t *s, uint64_t id);
int q_recv_stream(struct connection *c, qstream_t *s, bool fin, uint64_t off, const void *p, size_t sz);
int q_recv_max_stream(struct connection *c, qstream_t *s, uint64_t off);
int q_recv_stop(struct connection *c, qstream_t *s, int errnum);
int q_recv_reset(struct connection *c, qstream_t *s, int errnum, uint64_t off);
uint8_t *q_encode_stream(struct connection *c, qstream_t *s, uint8_t *p, uint8_t *e, qtx_packet_t *pkt);
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

bool q_pending_scheduler(struct connection *c);
uint8_t *q_encode_scheduler(struct connection *c, uint8_t *p, qtx_packet_t *pkt);
void q_commit_scheduler(struct connection *c, const qtx_packet_t *pkt);

void q_remove_stream(struct connection *c, qstream_t *s);

// Shutdown

void q_internal_shutdown(struct connection *c, int errnum);
int q_decode_close(struct connection *c, uint8_t hdr, qslice_t *s, tick_t now);
uint8_t *q_encode_close(struct connection *c, uint8_t *p, qtx_packet_t *pkt);
void q_commit_close(struct connection *c, qtx_packet_t *pkt);
void q_ack_close(struct connection *c);
void q_lost_close(struct connection *c);

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
