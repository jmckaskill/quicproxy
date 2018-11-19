#pragma once
#include "signature.h"
#include "cipher.h"
#include "bearssl_wrapper.h"
#include <cutils/char-array.h>
#include <stdint.h>

#define QUIC_VERSION UINT32_C(0xFF00000F)
#define DEFAULT_SERVER_ID_LEN 8
#define HELLO_MIN_PACKET_SIZE 1200
#define DEFAULT_PACKET_SIZE 1280
#define QUIC_RANDOM_SIZE 32
#define QUIC_MAX_KEYSHARE 2


#define VARINT_16 UINT16_C(0x4000)
#define VARINT_32 UINT32_C(0x80000000)
#define VARINT_64 UINT64_C(0xC000000000000000)

// packet types
#define LONG_HEADER_FLAG 0x80
#define INITIAL_PACKET 0xFF
#define RETRY_PACKET 0xFE
#define HANDSHAKE_PACKET 0xFD
#define PROTECTED_PACKET 0xFC

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


#define ALIGN_DOWN(type, u, sz) ((u) &~ ((type)(sz)-1))
#define ALIGN_UP(type, u, sz) ALIGN_DOWN(type, (u) + (sz) - 1, (sz))

static inline void *append(void *to, const void *from, size_t sz) {
	memcpy(to, from, sz);
	return (uint8_t*)to + sz;
}

typedef struct qslice qslice_t;
struct qslice {
	uint8_t *p;
	uint8_t *e;
};

static inline uint8_t encode_id_len(uint8_t len) {return len ? (len - 3) : 0;}
static inline uint8_t decode_id_len(uint8_t val) {return val ? (val + 3) : 0;}
uint8_t *encode_varint(uint8_t *p, uint64_t val);
int64_t decode_varint(qslice_t *s);
size_t packet_number_length(uint64_t val);
uint8_t *encode_packet_number(uint8_t *p, uint64_t val);
int64_t decode_packet_number(qslice_t *s);

int encode_client_hello(const qconnection_t *c, qslice_t *ps);
int encode_server_hello(const qconnection_t *c, qslice_t *ps);
int decode_client_hello(qslice_t *s, qconnect_request_t *h, const qcrypto_params_t *params);

struct encrypted_extensions {
	char todo;
};

int encode_certificates(qslice_t *s, const qsigner_class *const *signer);
int encode_verify(qslice_t *s, const qsignature_class *type, const uint8_t *sig, size_t len);
int encode_finished(qslice_t *s, const uint8_t *verify, size_t len);

#define CRYPTO_ERROR -1
#define CRYPTO_MORE 0

struct crypto_decoder {
	unsigned state;
	unsigned end;
	unsigned stack[4];
	unsigned have_bytes;
	uint8_t buf[3];
	uint8_t bufsz;
	uint8_t depth;
};

struct server_hello {
	uint16_t tls_version;
	uint16_t cipher;
	br_ec_public_key key;
	uint8_t random[QUIC_RANDOM_SIZE];
	uint8_t key_data[BR_EC_KBUF_PUB_MAX_SIZE];
};

struct verify {
	uint16_t algorithm;
	size_t sig_size;
	uint8_t signature[QUIC_MAX_SIG_SIZE];
	uint8_t msg_hash[QUIC_MAX_HASH_SIZE];
};

struct finished {
	size_t size;
	uint8_t verify[QUIC_MAX_HASH_SIZE];
	uint8_t msg_hash[QUIC_MAX_HASH_SIZE];
};

int decode_server_hello(struct crypto_decoder *d, struct server_hello *s, unsigned off, const void *data, size_t size);
int decode_certificates(struct crypto_decoder *d, const br_x509_class **x, unsigned off, const void *data, size_t size);
int decode_verify(struct crypto_decoder *d, struct verify *v, unsigned off, const void *data, size_t size);
int decode_finished(struct crypto_decoder *d, struct finished *f, unsigned off, const void *data, size_t size);




