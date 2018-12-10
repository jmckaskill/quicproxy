#pragma once

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4244)
#pragma warning(disable:4267)
#endif
#include "bearssl.h"
#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include <cutils/apc.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <limits.h>

#ifdef _MSC_VER
#define _WIN32_WINNT 0x600
#include <basetsd.h>
typedef SSIZE_T ssize_t;
#define SSIZE_T_MIN MINSSIZE_T
#else
#include <sys/types.h>
#endif

typedef struct logger log_t;
typedef struct qconnection_cfg qconnection_cfg_t;
typedef struct qconnect_request qconnect_request_t;
typedef struct qstream qstream_t;
typedef struct qtx_packet qtx_packet_t;

struct qconnection {uint64_t align;};
typedef struct qconnection qconnection_t;

struct connection;
struct handshake;
struct client_handshake;
struct server_handshake;

typedef struct qslice qslice_t;
struct qslice {
	uint8_t *p;
	uint8_t *e;
};

static inline uint8_t digest_size(const br_hash_class *digest_class) {
	return (uint8_t)(digest_class->desc >> BR_HASHDESC_OUT_OFF)
		& BR_HASHDESC_OUT_MASK;
}

static inline void *append_mem(void *to, const void *from, size_t sz) {
	memcpy(to, from, sz);
	return (char*)to + sz;
}

static inline void *append_bytes(void *to, uint8_t byte, size_t sz) {
	memset(to, byte, sz);
	return (char*)to + sz;
}

#define QUIC_MAX_SECRET_SIZE 32
#define QUIC_MAX_HASH_SIZE 32
#define QUIC_MAX_KEY_SIZE 32
#define QUIC_MAX_IV_SIZE 12
#define QUIC_TAG_SIZE 16
#define QUIC_MAX_SIG_SIZE 512 // allow for up to 4096 bit rsa keys
#define QUIC_RANDOM_SIZE 32
#define QUIC_DEFAULT_RTT (100 * 1000) // 100ms
#define QUIC_DEFAULT_IDLE_TIMEOUT (30 * 1000 * 1000) // 30s
#define QUIC_MIN_RTT ((tickdiff_t)1000) // 1 ms
#define QUIC_SHORT_ACK_TIMEOUT (1000) // 1 ms
#define QUIC_LONG_ACK_TIMEOUT (25000) // 25 ms
#define QUIC_MIN_TLP_TIMEOUT (10 * 1000)
#define QUIC_MIN_RTO_TIMEOUT (200 * 1000)
#define QUIC_ACK_DELAY_SHIFT 3 // = 8 us resolution
#define QUIC_TOKEN_TIMEOUT (10 * 1000 * 1000) // 10s

#define QUIC_MAX_IDS 8
#define QUIC_MAX_ADDR 3
#define QUIC_MAX_CERTIFICATES 8
#define QUIC_MAX_ALGORITHMS 32
#define QUIC_CRYPTO_BUF_SIZE 4096

#define QUIC_MAX_ADDRESS_SIZE 18

#define QUIC_MAX_KEYSHARE 2
#define QUIC_VERSION UINT32_C(0xFF00000F)
#define QUIC_GREASE_VERSION UINT32_C(0x4a5a6a7a)
#define DEFAULT_SERVER_ID_LEN 8
#define HELLO_MIN_PACKET_SIZE 1200
#define DEFAULT_PACKET_SIZE 1280
#define TLS_VERSION 0x304



#define QC_PARSE_ERROR -6
#define QC_WRONG_VERSION -5
#define QC_STATELESS_RETRY -4
#define QC_ERR_UNKNOWN_FRAME -3
#define CRYPTO_ERROR -2
#define QC_ERR_DROP -2
#define QC_MORE_DATA -1
#define QC_NO_ERROR 0
#define QC_ERR_INTERNAL 1
#define QC_ERR_SERVER_BUSY 2
#define QC_ERR_FLOW_CONTROL 3
#define QC_ERR_STREAM_ID 4
#define QC_ERR_STREAM_STATE 5
#define QC_ERR_FINAL_OFFSET 6
#define QC_ERR_FRAME_ENCODING 7
#define QC_ERR_TRANSPORT_PARAMETER 8
#define QC_ERR_VERSION_NEGOTIATION 9
#define QC_ERR_PROTOCOL_VIOLATION 0x0A
#define QC_ERR_INVALID_MIGRATION 0x0C

#define QC_ERR_TLS_OFFSET 0x100
#define QC_ERR_TLS_MAX 0x200
#define QC_ERR_TLS_UNEXPECTED_MESSAGE 0x10A
#define QC_ERR_TLS_BAD_RECORD_MAC 0x114
#define QC_ERR_TLS_RECORD_OVERFLOW 0x116
#define QC_ERR_TLS_HANDSHAKE_FAILURE 0x128
#define QC_ERR_TLS_BAD_CERTIFICATE 0x12A
#define QC_ERR_TLS_UNSUPPORTED_CERTIFICATE 0x12B
#define QC_ERR_TLS_CERTIFICATE_REVOKED 0x12C
#define QC_ERR_TLS_CERTIFICATE_EXPIRED 0x12D
#define QC_ERR_TLS_CERTIFICATE_UNKNOWN 0x12E
#define QC_ERR_TLS_ILLEGAL_PARAMETER 0x12F
#define QC_ERR_TLS_UNKNOWN_CA 0x130
#define QC_ERR_TLS_ACCESS_DENIED 0x131
#define QC_ERR_TLS_DECODE_ERROR 0x132
#define QC_ERR_TLS_DECRYPT_ERROR 0x133
#define QC_ERR_TLS_PROTOCOL_VERSION 0x146
#define QC_ERR_TLS_INSUFFICIENT_SECURITY 0x147
#define QC_ERR_TLS_INTERNAL_ERROR 0x150
#define QC_ERR_TLS_INAPPROPRIATE_FALLBACK 0x156
#define QC_ERR_TLS_USER_CANCELED 0x15A
#define QC_ERR_TLS_MISSING_EXTENSION 0x16D
#define QC_ERR_TLS_UNSUPPORTED_EXTENSION 0x16E
#define QC_ERR_TLS_UNRECOGNIZED_NAME 0x170
#define QC_ERR_TLS_BAD_CERTIFICATE_STATUS_RESPONSE 0x171
#define QC_ERR_TLS_UNKNOWN_PSK_IDENTITY 0x173
#define QC_ERR_TLS_CERTIFICATE_REQUIRED 0x174
#define QC_ERR_TLS_NO_APPLICATION_PROTOCOL 0x178

#define QC_ERR_QUIC_MAX 0x1000

#define QC_ERR_APP_OFFSET 0x10000
#define QC_ERR_APP_END 0x20000

#define QC_ERR_BR_X509_OFFSET 0x20000
#define QC_ERR_BR_X509_MAX 0x21000

#define QC_ERR_IDLE_TIMEOUT 0x30000

