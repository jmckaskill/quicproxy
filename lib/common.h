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

#include <cutils/endian.h>
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
typedef unsigned long qmicrosecs_t;
typedef struct qconnection qconnection_t;
typedef struct qconnect_request qconnect_request_t;

static inline size_t digest_size(const br_hash_class *digest_class) {
	return (size_t)(digest_class->desc >> BR_HASHDESC_OUT_OFF)
		& BR_HASHDESC_OUT_MASK;
}

static inline void *append(void *to, const void *from, size_t sz) {
	memcpy(to, from, sz);
	return (uint8_t*)to + sz;
}

#define ALIGN_DOWN(type, u, sz) ((u) &~ ((type)(sz)-1))
#define ALIGN_UP(type, u, sz) ALIGN_DOWN(type, (u) + (sz) - 1, (sz))

#define QUIC_MAX_SECRET_SIZE 32
#define QUIC_MAX_HASH_SIZE 32
#define QUIC_MAX_KEY_SIZE 32
#define QUIC_MAX_IV_SIZE 12
#define QUIC_TAG_SIZE 16
#define QUIC_MAX_SIG_SIZE 512 // allow for up to 4096 bit rsa keys
#define QUIC_RANDOM_SIZE 32
#define QUIC_DEFAULT_RTT (100 * 1000) // 100ms
#define QUIC_DEFAULT_IDLE_TIMEOUT (15 * 1000 * 1000) // 15s


#define QUIC_MAX_IDS 8
#define QUIC_MAX_ADDR 3
#define QUIC_MAX_CERTIFICATES 8
#define QUIC_MAX_ALGORITHMS 32
#define QUIC_CRYPTO_BUF_SIZE 4096
#define QUIC_CRYPTO_PACKETS 8

#define QUIC_ADDRESS_SIZE 19 // +1 for size

#define QUIC_MAX_KEYSHARE 2
#define QUIC_VERSION UINT32_C(0xFF00000F)
#define DEFAULT_SERVER_ID_LEN 8
#define HELLO_MIN_PACKET_SIZE 1200
#define DEFAULT_PACKET_SIZE 1280
#define TLS_VERSION 0x304

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

#define STREAM_SERVER 1
#define STREAM_UNI 2

