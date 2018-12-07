#pragma once
#include "common.h"
#include "signature.h"
#include "cipher.h"


enum qcrypto_level {
	QC_INITIAL,
	QC_HANDSHAKE,
	QC_PROTECTED,
};

static inline uint8_t encode_id_len(uint8_t len) {return len ? (len - 3) : 0;}
static inline uint8_t decode_id_len(uint8_t val) {return val ? (val + 3) : 0;}
uint8_t *encode_varint(uint8_t *p, uint64_t val);
int decode_varint(qslice_t *s, uint64_t *pval);
size_t packet_number_length(uint64_t val);
uint8_t *encode_packet_number(uint8_t *p, uint64_t base, uint64_t val);
uint8_t *decode_packet_number(uint8_t *p, uint64_t base, uint64_t *pval);

int encode_client_hello(const struct client_handshake *ch, qslice_t *ps);
int encode_server_hello(const struct server_handshake *sh, qslice_t *ps);
int encode_encrypted_extensions(const struct server_handshake *sh, qslice_t *ps);
int decode_client_hello(void *data, size_t len, qconnect_request_t *req, const qconnection_cfg_t *cfg);

int encode_certificates(qslice_t *s, const qsigner_class *const *signer);
int encode_verify(qslice_t *s, const qsignature_class *type, const void *sig, size_t len);
int encode_finished(qslice_t *s, const br_hash_class *digest, const void *verify);
uint8_t *encode_client_finished(struct connection *c, uint8_t *p);

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


const br_hash_class **init_message_hash(struct handshake *h, const br_hash_class *hash);
void init_protected_keys(struct handshake *h, const uint8_t *msg_hash);
int q_decode_crypto(struct connection *c, enum qcrypto_level level, qslice_t *frame_data, tick_t rxtime);

qtx_packet_t *q_send_client_hello(struct client_handshake *ch, const br_prng_class **rand, tick_t now);
int q_send_server_hello(struct server_handshake *sh, const br_prng_class **rand, const br_ec_public_key *pk, tick_t now);






