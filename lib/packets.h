#pragma once
#include "bearssl_wrapper.h"
#include "quic.h"
#include <cutils/char-array.h>
#include <stdint.h>

#define QUIC_VERSION UINT32_C(0xFF00000F)
#define DEFAULT_SERVER_ID_LEN 8

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

// TLS records
#define TLS_RECORD_HEADER_SIZE 4
#define CLIENT_HELLO 1
#define SERVER_HELLO 2
#define NEW_SESSION_TICKET 4
#define END_OF_EARLY_DATA 5
#define ENCRYPTED_EXTENSIONS 6
#define CERTIFICATE 11
#define CERTIFICATE_REQUEST 13
#define CERTIFICATE_VERIFY 15
#define FINISHED 20
#define KEY_UPDATE 24
#define MESSAGE_HASH 254

#define TLS_LEGACY_VERSION 0x303
#define TLS_VERSION 0x304
#define TLS_HELLO_RANDOM_SIZE 32

// TLS ciphers
#define TLS_AES_128_GCM_SHA256 0x1301

#define EC_KEY_UNCOMPRESSED 4

// TLS compression methods
#define TLS_COMPRESSION_NULL 0

// TLS signature algorithms
#define RSA_PKCS1_SHA256 0x0401
#define RSA_PKCS1_SHA384 0x0501
#define RSA_PKCS1_SHA512 0x0601
#define ECDSA_SECP256R1_SHA256 0x0403
#define ECDSA_SECP384R1_SHA384 0x0503
#define ECDSA_SECP512R1_SHA512 0x0603
#define ED25519 0x0807
#define ED448 0x0808
#define RSA_PSS_SHA256 0x0809
#define RSA_PSS_SHA384 0x080A
#define RSA_PSS_SHA512 0x080B

// TLS extensions
#define TLS_EXTENSION_HEADER_SIZE 4
#define SERVER_NAME 0
#define MAX_FRAGMENT_LENGTH 1
#define STATUS_REQUEST 5
#define SUPPORTED_GROUPS 10
#define SIGNATURE_ALGORITHMS 13
#define USE_SRTP 14
#define HEARTBEAT 15
#define APP_PROTOCOL 16
#define SIGNED_CERTIFICATE_TIMESTAMP 18
#define CLIENT_CERTIFICATE_TYPE 19
#define SERVER_CERTIFICATE_TYPE 20
#define TLS_PADDING 21
#define PRE_SHARED_KEY 41
#define EARLY_DATA 42
#define SUPPORTED_VERSIONS 43
#define COOKIE 44
#define PSK_KEY_EXCHANGE_MODES 45
#define CERTIFICATE_AUTHORITIES 47
#define OID_FILTERS 48
#define POST_HANDSHAKE_AUTH 49
#define SIGNATURE_ALGORITHMS_CERT 50
#define KEY_SHARE 51
#define QUIC_TRANSPORT_PARAMETERS 0xFFA5

// server name
#define HOST_NAME_TYPE 0

uint8_t encode_id_len(uint8_t len);
uint8_t decode_id_len(uint8_t val);
uint8_t *encode_varint(uint8_t *p, uint64_t val);
int64_t decode_varint(qslice_t *s);
uint8_t *encode_packet_number(uint8_t *p, uint64_t val);
int64_t decode_packet_number(qslice_t *s);

struct client_hello {
	const uint8_t *random;
	qslice_t server_name;
	qslice_t ciphers;
	qslice_t groups;
	qslice_t algorithms;
	size_t key_num;
	br_ec_public_key keys[QUIC_MAX_KEYSHARE];
};

int encode_client_hello(qslice_t *s, const struct client_hello *h);
int decode_client_hello(qslice_t s, struct client_hello *h);

struct server_hello {
	const uint8_t *random;
	uint16_t cipher;
	br_ec_public_key key;
};

int encode_server_hello(qslice_t *s, const struct server_hello *h);
int decode_server_hello(qslice_t s, struct server_hello *h);

static inline void *append(void *to, const void *from, size_t sz) {
	memcpy(to, from, sz);
	return (uint8_t*)to + sz;
}



