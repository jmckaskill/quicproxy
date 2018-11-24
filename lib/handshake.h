#pragma once
#include "common.h"
#include "signature.h"
#include "cipher.h"

// By default we support the 5 ECDHE groups in TLS 1.3
// Priority is given to x22519 and secp256r1
#define TLS_DEFAULT_GROUPS "\x1D\x17\x18\x19\x1E"

typedef struct qconnect_params qconnect_params_t;
struct qconnect_params {
	const char *groups;
	const qcipher_class *const *ciphers;
	const qsignature_class *const *signatures;
	// these refer to the initial maximum data the remote is allowed to send us
	uint32_t stream_data_bidi_local; // for bidi streams initiated by us
	uint32_t stream_data_bidi_remote; // for bidi streams initiated by the remote
	uint32_t stream_data_uni; // for uni streams initiated by the remote
	// these refer to the initial maximum streams the remote is allowed to initiate
	uint32_t bidi_streams;
	uint32_t uni_streams;
	// the initial maximum of the total data sent to us
	uint32_t max_data;
	qmicrosecs_t idle_timeout;
};


enum qcrypto_level {
	QC_INITIAL,
	QC_HANDSHAKE,
	QC_PROTECTED,
	QC_UNKNOWN,
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
int decode_crypto(qconnection_t *c, enum qcrypto_level level, qslice_t *frame_data);




