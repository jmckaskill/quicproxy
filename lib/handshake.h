#pragma once
#include "common.h"
#include "signature.h"
#include "cipher.h"


enum qcrypto_level {
	QC_INITIAL,
	QC_HANDSHAKE,
	QC_PROTECTED,
};

typedef struct qslice qslice_t;
struct qslice {
	uint8_t *p;
	uint8_t *e;
};

static inline uint8_t encode_id_len(uint8_t len) {return len ? (len - 3) : 0;}
static inline uint8_t decode_id_len(uint8_t val) {return val ? (val + 3) : 0;}
uint8_t *encode_varint(uint8_t *p, uint64_t val);
int decode_varint(qslice_t *s, uint64_t *pval);
size_t packet_number_length(uint64_t val);
uint8_t *encode_packet_number(uint8_t *p, uint64_t val);
int decode_packet_number(qslice_t *s, uint64_t *pval);

int encode_client_hello(const qconnection_t *c, qslice_t *ps);
int encode_server_hello(const qconnection_t *c, qslice_t *ps);
int encode_encrypted_extensions(const qconnection_t *c, qslice_t *ps);
int decode_client_hello(qslice_t *s, qconnect_request_t *h, const qconnect_params_t *params);

int encode_certificates(qslice_t *s, const qsigner_class *const *signer);
int encode_verify(qslice_t *s, const qsignature_class *type, const void *sig, size_t len);
int encode_finished(qslice_t *s, const br_hash_class *digest, const void *verify);

#define QC_PARSE_ERROR -6
#define QC_WRONG_VERSION -5
#define QC_STATELESS_RETRY -4
#define QC_ERR_UNKNOWN_FRAME -3
#define CRYPTO_ERROR -2
#define QC_ERR_DROP -1
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

#define QC_ERR_IDLE_TIMEOUT 0x1000

#define QC_ERR_BR_X509_OFFSET 0x2000
#define QC_ERR_BR_X509_MAX 0x2100


struct crypto_decoder {
	int level;
	uint32_t next;
	int state;
	uint32_t end;
	uint32_t stack[4];
	uint32_t have_bytes;
	uint8_t buf[3];
	uint8_t bufsz;
	uint8_t depth;
	uint8_t msg_hash[QUIC_MAX_HASH_SIZE];

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
		} v;

		struct {
			size_t len;
			uint8_t fin[QUIC_MAX_HASH_SIZE];
		} f;
	} u;
};

const br_hash_class **init_cipher(qconnection_t *c, const qcipher_class *cipher);
void init_client_decoder(qconnection_t *c);
void init_server_decoder(qconnection_t *c);
void init_protected_keys(qconnection_t *c, const uint8_t *msg_hash);
int decode_crypto(qconnection_t *c, enum qcrypto_level level, qslice_t *frame_data);




