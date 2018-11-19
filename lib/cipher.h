#pragma once
#include "common.h"

typedef struct qcipher_class qcipher_class;
struct qcipher_class {
	uint16_t cipher;
	uint8_t key_size;
	uint8_t iv_size;
	uint8_t tag_size;
	const br_hash_class *hash;
	void(*init)(const qcipher_class **vt, const void *pn_key, const void *data_key);
	void(*protect)(const qcipher_class **vt, void *pktnum, size_t num_sz, size_t pay_sz);
	uint32_t(*decrypt)(const qcipher_class **vt, uint64_t pktnum, const void *iv, uint8_t *pkt, uint8_t *enc, uint8_t *tag);
	void(*encrypt)(const qcipher_class **vt, uint64_t pktnum, const void *iv, uint8_t *pkt, uint8_t *enc, uint8_t *tag);
};

const qcipher_class *find_cipher(const qcipher_class *const *s, uint16_t code);

// TLS_AES_128_GCM_SHA256 & TLS_AES_256_GCM_SH384
typedef struct qcipher_aes_gcm qcipher_aes_gcm;
struct qcipher_aes_gcm {
	const qcipher_class *vtable;
	br_aes_gen_ctr_keys data;
	br_aes_gen_ctr_keys pn;
	br_gcm_context gcm;
};

extern const qcipher_class TLS_AES_128_GCM_SHA256;
extern const qcipher_class TLS_AES_256_GCM_SHA384;

// TLS_AES_128_CCM_SHA256
typedef struct qcipher_aes_ccm qcipher_aes_ccm;
struct qcipher_aes_ccm {
	const qcipher_class *vtable;
	br_aes_gen_ctrcbc_keys data;
	br_aes_gen_ctr_keys pn;
	br_ccm_context ccm;
};

extern const qcipher_class TLS_AES_128_CCM_SHA256;

// TLS_CHACHA20_POLY1305_SHA256
typedef struct qcipher_chacha20 qcipher_chacha20;
struct qcipher_chacha20 {
	const qcipher_class *vtable;
	const void *pn_key;
	const void *data_key;
};

extern const qcipher_class TLS_CHACHA20_POLY1305_SHA256;
extern const qcipher_class *TLS_DEFAULT_CIPHERS[];


typedef struct qkeyset qkeyset_t;
struct qkeyset {
	union {
		const qcipher_class *vtable;
		qcipher_aes_gcm aes_gcm;
		qcipher_aes_ccm aes_ccm;
		qcipher_chacha20 chacha20;
	} u;
	uint8_t secret[QUIC_MAX_SECRET_SIZE];
	uint8_t pn_key[QUIC_MAX_KEY_SIZE];
	uint8_t data_key[QUIC_MAX_KEY_SIZE];
	uint8_t data_iv[QUIC_MAX_IV_SIZE];
};

