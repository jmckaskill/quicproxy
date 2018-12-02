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
#define QPKT_PATH_CHALLENGE	(1 << 0)
#define QPKT_PATH_RESPONSE	(1 << 1)
#define QPKT_ACK				(1 << 2)
#define QPKT_FIN				(1 << 3)
#define QPKT_RST				(1 << 4)
#define QPKT_STOP			(1 << 5)
#define QPKT_STREAM_DATA		(1 << 6)
#define QPKT_MAX_DATA		(1 << 7)
#define QPKT_MAX_ID_UNI		(1 << 8)
#define QPKT_MAX_ID_BIDI		(1 << 9)
#define QPKT_NEW_TOKEN		(1 << 10)
#define QPKT_RETRANSMIT		(1 << 11)
#define QPKT_CLOSE			(1 << 12)
#define QPKT_NEW_ID			(1 << 13)
#define QPKT_RETIRE_ID		(1 << 14)
#define QPKT_CRYPTO			(1 << 15)

// stream flags
#define QS_TX_COMPLETE (1 << 0)
#define QS_RX_COMPLETE (1 << 1)
#define QS_TX_QUEUED   (1 << 2)
#define QS_TX_PENDING  (1 << 3)
#define QS_TX_FIN      (1 << 4)
#define QS_TX_FIN_SENT (1 << 5)
#define QS_RX_FIN_ACK  (1 << 6)
#define QS_RX_FIN      (1 << 7)
#define QS_TX_RST      (1 << 8)
#define QS_TX_RST_SENT (1 << 9)
#define QS_RX_RST_ACK  (1 << 10)
#define QS_RX_RST      (1 << 11)
#define QS_TX_STOP     (1 << 12)
#define QS_TX_STOP_SENT (1 << 13)
#define QS_RX_STOP_ACK (1 << 14)
#define QS_RX_STOP     (1 << 15)
#define QS_RX_DATA_ACK (1 << 16)
#define QS_TX_DIRTY    (1 << 17)

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


#define ARRAYSZ(A) (sizeof(A) / sizeof((A)[0]))
#define ALIGN_DOWN(type, u, sz) ((u) &~ ((type)(sz)-1))
#define ALIGN_UP(type, u, sz) ALIGN_DOWN(type, (u) + (sz) - 1, (sz))
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

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
	bool handshake_complete;
	bool closing;
	bool draining;
	bool have_srtt;
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
	uint64_t next_id[4];
	uint64_t max_id[4];
	rbtree pending_streams[2];
	rbtree tx_streams;
	uint64_t tx_max_data;
	uint64_t data_sent;
	uint64_t rx_max_data;
	uint64_t data_received;
	uint8_t tx_flags;

	// congestion window
	uint64_t congestion_window;
	uint64_t bytes_in_flight;
	uint64_t end_of_recovery;
	uint64_t slow_start_threshold;
	uint64_t ecn_ce_counter;

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

	const br_hash_class **msgs;
	br_sha256_context msg_sha256;
	br_sha384_context msg_sha384;

	uint8_t *conn_buf_end;
};

struct client_handshake {
	struct handshake h;
	qtx_packet_t init_pkts[16];
	qtx_packet_t hs_pkts[8];

	union {
		struct {
			uint16_t tls_version;
			br_ec_public_key k;
			uint8_t key_data[BR_EC_KBUF_PUB_MAX_SIZE];
		} sh;

		struct {
			uint16_t algorithm;
			size_t len;
			uint8_t sig[QUIC_MAX_SIG_SIZE];
			const br_x509_class **x;
		} v;

		struct {
			size_t len;
			uint8_t fin[QUIC_MAX_HASH_SIZE];
		} f;
	} u;
	const char *server_name;
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

void q_receive_packet(struct connection *c, enum qcrypto_level level, uint64_t num, tick_t rxtime);

struct long_packet {
	enum qcrypto_level level;
	const qcipher_class **key;
	size_t crypto_off;
	const uint8_t *crypto_data;
	size_t crypto_size;
	bool pad;
};

qtx_packet_t *q_encode_long_packet(struct handshake *h, qslice_t *s, struct long_packet *p, tick_t now);

struct short_packet {
	qstream_t *stream;
	uint64_t stream_off;
	int close_errnum;
	bool force_ack;
	bool ignore_cwnd;
	bool ignore_closing;
	bool ignore_draining;
	bool send_close;
	bool send_ack;
	bool send_stop;
};

int q_send_short_packet(struct connection *c, struct short_packet *s, tick_t *pnow);

// Streams
void q_setup_local_stream(struct connection *c, qstream_t *s, uint64_t id);
void q_setup_remote_stream(struct connection *c, qstream_t *s, uint64_t id);
int q_recv_stream(struct connection *c, qstream_t *s, bool fin, uint64_t off, const void *p, size_t sz);
int q_recv_max_stream(struct connection *c, qstream_t *s, uint64_t off);
int q_recv_stop(struct connection *c, qstream_t *s, int errnum);
int q_recv_reset(struct connection *c, qstream_t *s, int errnum, uint64_t off);
int q_encode_stream(struct connection *c, qslice_t *p, const qstream_t *s, uint64_t *poff, qtx_packet_t *pkt);
void q_commit_stream(struct connection *c, qstream_t *s, qtx_packet_t *pkt);
void q_ack_stream(struct connection *c, qtx_packet_t *pkt);
void q_lost_stream(struct connection *c, qtx_packet_t *pkt);
size_t q_stream_cwnd_size(const qtx_packet_t *pkt);

// Scheduler

void q_update_scheduler_from_cfg(struct connection *c);
int q_send_data(struct connection *c, int ignore_cwnd_pkts, tick_t now);

int q_decode_stream(struct connection *c, uint8_t hdr, qslice_t *s);
int q_decode_reset(struct connection *c, qslice_t *s);
int q_decode_stop(struct connection *c, qslice_t *p);
int q_decode_stream_data(struct connection *c, qslice_t *s);
int q_decode_max_data(struct connection *c, qslice_t *s);
int q_decode_max_id(struct connection *c, qslice_t *p);

size_t q_scheduler_cwnd_size(const qtx_packet_t *pkt);
bool q_pending_scheduler(struct connection *c);
int q_encode_scheduler(struct connection *c, qslice_t *p, qtx_packet_t *pkt);
void q_commit_scheduler(struct connection *c, const qtx_packet_t *pkt);
void q_ack_scheduler(struct connection *c, const qtx_packet_t *pkt);
void q_lost_scheduler(struct connection *c, const qtx_packet_t *pkt);

void q_remove_stream(struct connection *c, qstream_t *s);

// Shutdown

void q_internal_shutdown(struct connection *c, int errnum, tick_t now);
void q_send_close(struct connection *c, tick_t now);
int q_decode_close(struct connection *c, uint8_t hdr, qslice_t *s, tick_t now);
int q_encode_close(struct connection *c, qslice_t *p, qtx_packet_t *pkt);
void q_ack_close(struct connection *c);
void q_lost_close(struct connection *c, tick_t now);

// Timers

void q_fast_async_ack(struct connection *c, tick_t now);
void q_async_ack(struct connection *c, tick_t now);
void q_draining_ack(struct connection *c, tick_t now);

void q_start_probe_timer(struct connection *c, tick_t now);
void q_start_ping_timeout(struct connection *c, tick_t now);
void q_async_send_data(struct connection *c);
void q_start_idle_timer(struct connection *c, tick_t now);

void q_start_handshake(struct handshake *h, tick_t now);
void q_start_runtime(struct handshake *h, tick_t now);
void q_start_shutdown(struct connection *c, tick_t now);
void q_async_shutdown(struct connection *c);

// Congestion
void q_cwnd_init(struct connection *c);
void q_cwnd_sent(struct connection *c, const qtx_packet_t *pkt);
void q_cwnd_ack(struct connection *c, uint64_t pktnum, const qtx_packet_t *pkt);
void q_cwnd_ecn(struct connection *c, uint64_t pktnum, uint64_t ecn_ce);
void q_cwnd_lost(struct connection *c, const qtx_packet_t *pkt);
void q_cwnd_largest_lost(struct connection *c, uint64_t pktnum);
void q_cwnd_rto_verified(struct connection *c, uint64_t pktnum);
size_t q_cwnd_allowed_bytes(struct connection *c);


static inline uint64_t q_encode_ack_delay(tickdiff_t delay, unsigned exp) {
	return delay >> (exp ? exp : QUIC_ACK_DELAY_SHIFT);
}

static inline tickdiff_t q_decode_ack_delay(uint64_t raw, unsigned exp) {
	return (tickdiff_t)(raw << (exp ? exp : QUIC_ACK_DELAY_SHIFT));
}
