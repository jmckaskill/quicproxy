#pragma once
#include "common.h"

// By default we support the 5 ECDHE groups in TLS 1.3
// Priority is given to x22519 and secp256r1
#define TLS_DEFAULT_GROUPS "\x1D\x17\x18\x19"

typedef struct qcipher_class qcipher_class;
struct qcipher_class {
	uint16_t cipher;
	const br_hash_class *hash;
	void(*init)(const qcipher_class **vt, const void *traffic);
	void(*protect)(const qcipher_class **vt, void *pktnum, size_t num_sz, size_t pay_sz);
	uint32_t(*decrypt)(const qcipher_class **vt, uint64_t pktnum, uint8_t *pkt, uint8_t *enc, uint8_t *tag);
	void(*encrypt)(const qcipher_class **vt, uint64_t pktnum, uint8_t *pkt, uint8_t *enc, uint8_t *tag);
};

const qcipher_class *find_cipher(const qcipher_class *const *s, uint16_t code);

// TLS_AES_128_GCM_SHA256 & TLS_AES_256_GCM_SH384
typedef struct qcipher_aes_gcm qcipher_aes_gcm;
struct qcipher_aes_gcm {
	const qcipher_class *vtable;
	br_aes_gen_ctr_keys data;
	br_aes_gen_ctr_keys pn;
	br_gcm_context gcm;
	uint8_t data_iv[12];
};

extern const qcipher_class TLS_AES_128_GCM_SHA256;
extern const qcipher_class TLS_AES_256_GCM_SHA384;

void init_aes_128_gcm(qcipher_aes_gcm *c, const void *traffic);

// TLS_AES_128_CCM_SHA256
typedef struct qcipher_aes_ccm qcipher_aes_ccm;
struct qcipher_aes_ccm {
	const qcipher_class *vtable;
	br_aes_gen_ctrcbc_keys data;
	br_aes_gen_ctr_keys pn;
	br_ccm_context ccm;
	uint8_t data_iv[12];
};

extern const qcipher_class TLS_AES_128_CCM_SHA256;

// TLS_CHACHA20_POLY1305_SHA256
typedef struct qcipher_chacha20 qcipher_chacha20;
struct qcipher_chacha20 {
	const qcipher_class *vtable;
	uint8_t pn_key[32];
	uint8_t data_key[32];
	uint8_t data_iv[12];
};

extern const qcipher_class TLS_CHACHA20_POLY1305_SHA256;
extern const qcipher_class *TLS_DEFAULT_CIPHERS[];

typedef union qcipher_compat qcipher_compat;
union qcipher_compat {
	const qcipher_class *vtable;
	qcipher_aes_gcm aes_gcm;
	qcipher_aes_ccm aes_ccm;
	qcipher_chacha20 chacha20;
};

