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

#ifdef _MSC_VER
typedef ptrdiff_t ssize_t;
#else
#include <sys/types.h>
#endif

typedef struct logger log_t;
typedef struct qconnection_cfg qconnection_cfg_t;
typedef struct qconnect_request qconnect_request_t;
typedef struct qslice qslice_t;
typedef struct qstream qstream_t;
typedef struct qtx_packet qtx_packet_t;

struct qconnection {uint64_t align;};
typedef struct qconnection qconnection_t;

struct connection;
struct handshake;
struct client_handshake;
struct server_handshake;

static inline size_t digest_size(const br_hash_class *digest_class) {
	return (size_t)(digest_class->desc >> BR_HASHDESC_OUT_OFF)
		& BR_HASHDESC_OUT_MASK;
}

static inline void *append(void *to, const void *from, size_t sz) {
	memcpy(to, from, sz);
	return (uint8_t*)to + sz;
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

