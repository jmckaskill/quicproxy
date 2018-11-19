#pragma once
#include "common.h"
#include "signature.h"
#include "cipher.h"

typedef struct qcrypto_params qcrypto_params_t;
struct qcrypto_params {
	const char *groups;
	const qcipher_class *const *ciphers;
	const qsignature_class *const *signatures;
};

extern const qcrypto_params_t TLS_DEFAULT_PARAMS;


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




