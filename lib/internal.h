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
#define QTX_PKT_PATH_CHALLENGE	(1 << 0)
#define QTX_PKT_PATH_RESPONSE	(1 << 1)
#define QTX_PKT_ACK				(1 << 2)
#define QTX_PKT_FIN				(1 << 3)
#define QTX_PKT_RST				(1 << 4)
#define QTX_PKT_STOP			(1 << 5)
#define QTX_PKT_STREAM_DATA		(1 << 6)
#define QTX_PKT_MAX_DATA		(1 << 7)
#define QTX_PKT_MAX_ID_UNI		(1 << 8)
#define QTX_PKT_MAX_ID_BIDI		(1 << 9)
#define QTX_PKT_NEW_TOKEN		(1 << 10)
#define QTX_PKT_RETRANSMIT		(1 << 11)
#define QTX_PKT_CLOSE			(1 << 12)
#define QTX_PKT_NEW_ID			(1 << 13)
#define QTX_PKT_RETIRE_ID		(1 << 14)
#define QTX_PKT_CRYPTO			(1 << 15)

// stream flags
#define QTX_COMPLETE (1 << 0)
#define QRX_COMPLETE (1 << 1)
#define QTX_QUEUED   (1 << 2)
#define QTX_PENDING  (1 << 3)
#define QTX_FIN      (1 << 4)
#define QTX_FIN_SENT (1 << 5)
#define QRX_FIN_ACK  (1 << 6)
#define QRX_FIN      (1 << 7)
#define QTX_RST      (1 << 8)
#define QTX_RST_SENT (1 << 9)
#define QRX_RST_ACK  (1 << 10)
#define QRX_RST      (1 << 11)
#define QTX_STOP     (1 << 12)
#define QTX_STOP_SENT (1 << 13)
#define QRX_STOP_ACK (1 << 14)
#define QRX_STOP     (1 << 15)
#define QRX_DATA_ACK (1 << 16)
#define QTX_DIRTY    (1 << 17)

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



#define ALIGN_DOWN(type, u, sz) ((u) &~ ((type)(sz)-1))
#define ALIGN_UP(type, u, sz) ALIGN_DOWN(type, (u) + (sz) - 1, (sz))
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

// Packet sending

void q_receive_packet(qconnection_t *c, enum qcrypto_level level, uint64_t num, tick_t rxtime);

struct long_packet {
	enum qcrypto_level level;
	const qcipher_class **key;
	size_t crypto_off;
	const uint8_t *crypto_data;
	size_t crypto_size;
	bool pad;
};

qtx_packet_t *q_encode_long_packet(qconnection_t *c, qslice_t *s, struct long_packet *p, tick_t now);

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

int q_send_short_packet(qconnection_t *c, struct short_packet *s, tick_t *pnow);

// Streams
void q_setup_local_stream(qstream_t *s, uint64_t id, uint64_t max_bidi_data, uint64_t max_uni_data);
void q_setup_remote_stream(qstream_t *s, uint64_t id, uint64_t max_bidi_data);
int q_recv_stream(qconnection_t *c, qstream_t *s, bool fin, uint64_t off, const void *p, size_t sz);
int q_recv_max_stream(qconnection_t *c, qstream_t *s, uint64_t off);
int q_recv_stop(qconnection_t *c, qstream_t *s, int errnum);
int q_recv_reset(qconnection_t *c, qstream_t *s, int errnum, uint64_t off);
int q_encode_stream(qconnection_t *c, qslice_t *p, qstream_t *s, uint64_t *poff, qtx_packet_t *pkt);
void q_ack_stream(qconnection_t *c, qtx_packet_t *pkt);
void q_lost_stream(qconnection_t *c, qtx_packet_t *pkt);

// Scheduler

void q_update_scheduler_from_cfg(qconnection_t *c);
int q_send_data(qconnection_t *c, int ignore_cwnd_pkts, tick_t now);

int q_decode_stream(qconnection_t *c, uint8_t hdr, qslice_t *s);
int q_decode_reset(qconnection_t *c, qslice_t *s);
int q_decode_stop(qconnection_t *c, qslice_t *p);
int q_decode_stream_data(qconnection_t *c, qslice_t *s);
int q_decode_max_data(qconnection_t *c, qslice_t *s);
int q_decode_max_id(qconnection_t *c, qslice_t *p);

int q_encode_max_data(qconnection_t *c, qslice_t *p, qtx_packet_t *pkt);
void q_ack_max_data(qconnection_t *c, const qtx_packet_t *pkt);
void q_lost_max_data(qconnection_t *c, const qtx_packet_t *pkt);

int q_encode_max_id(qconnection_t *c, qslice_t *p, qtx_packet_t *pkt);
void q_ack_max_id(qconnection_t *c, const qtx_packet_t *pkt);
void q_lost_max_id(qconnection_t *c, const qtx_packet_t *pkt);

void q_remove_stream(qconnection_t *c, qstream_t *s);

// Shutdown

void q_internal_shutdown(qconnection_t *c, int errnum, tick_t now);
void q_send_close(qconnection_t *c, tick_t now);
int q_decode_close(qconnection_t *c, uint8_t hdr, qslice_t *s, tick_t now);
int q_encode_close(qconnection_t *c, qslice_t *p, qtx_packet_t *pkt);
void q_ack_close(qconnection_t *c);
void q_lost_close(qconnection_t *c, tick_t now);

// Timers

void q_fast_async_ack(qconnection_t *c, tick_t now);
void q_async_ack(qconnection_t *c, tick_t now);
void q_draining_ack(qconnection_t *c, tick_t now);

void q_start_probe_timer(qconnection_t *c, tick_t now);
void q_start_ping_timeout(qconnection_t *c, tick_t now);
void q_async_send_data(qconnection_t *c);
void q_start_idle_timer(qconnection_t *c, tick_t now);

void q_start_handshake(qconnection_t *c, tick_t now);
void q_start_runtime(qconnection_t *c, tick_t now);
void q_start_shutdown(qconnection_t *c, tick_t now);
void q_async_shutdown(qconnection_t *c);

static inline uint64_t q_encode_ack_delay(tickdiff_t delay, unsigned exp) {
	return delay >> (exp ? exp : QUIC_ACK_DELAY_SHIFT);
}

static inline tickdiff_t q_decode_ack_delay(uint64_t raw, unsigned exp) {
	return (tickdiff_t)(raw << (exp ? exp : QUIC_ACK_DELAY_SHIFT));
}