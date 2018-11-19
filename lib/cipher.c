#include "cipher.h"

static void get_nonce_12(uint8_t *nonce, uint64_t pktnum, const void *iv) {
	write_big_32(nonce, 0);
	write_big_64(nonce + 4, pktnum);
	for (int i = 0; i < sizeof(nonce); i++) {
		nonce[i] ^= ((uint8_t*)iv)[i];
	}
}

static void init_aes_gcm(qcipher_aes_gcm *c, const void *pn_key, const void *data_key, size_t key_size) {
	br_ghash gh = br_ghash_pclmul_get();
	if (!gh) {
		gh = &br_ghash_ctmul;
	}
	const br_block_ctr_class *b = br_aes_x86ni_ctr_get_vtable();
	if (!b) {
		b = &br_aes_big_ctr_vtable;
	}
	b->init(&c->pn.vtable, pn_key, key_size);
	b->init(&c->data.vtable, data_key, key_size);
	br_gcm_init(&c->gcm, &c->data.vtable, gh);
}

static void init_aes_128_gcm_sha256(const qcipher_class **vt, const void *pn_key, const void *data_key) {
	qcipher_aes_gcm *c = (qcipher_aes_gcm*)vt;
	c->vtable = &TLS_AES_128_GCM_SHA256;
	init_aes_gcm(c, pn_key, data_key, 128/8);
}

static void init_aes_256_gcm_sha384(const qcipher_class **vt, const void *pn_key, const void *data_key) {
	qcipher_aes_gcm *c = (qcipher_aes_gcm*)vt;
	c->vtable = &TLS_AES_256_GCM_SHA384;
	init_aes_gcm(c, pn_key, data_key, 256/8);
}

static void protect_aes_gcm(const qcipher_class **vt, void *pktnum, size_t num_sz, size_t pay_sz) {
	// bearssl takes the AES CTR IV as 12B IV | 4B counter
	// QUIC wants to provide a 16B IV so we need to break them apart again from the sample
	qcipher_aes_gcm *c = (qcipher_aes_gcm*)vt;
	char *sample = (char*)pktnum + ((pay_sz < 20) ? (pay_sz - 16) : 4);
	c->pn.vtable->run(&c->pn.vtable, sample, big_32((char*)sample + 12), pktnum, num_sz);
}

static uint32_t decrypt_aes_gcm(const qcipher_class **vt, uint64_t pktnum, const void *iv, const uint8_t *pkt, const uint8_t *enc, const uint8_t *tag) {
	qcipher_aes_gcm *c = (qcipher_aes_gcm*)vt;
	uint8_t nonce[12];
	get_nonce_12(nonce, pktnum, iv);
	br_gcm_reset(&c->gcm, nonce, sizeof(nonce));
	br_gcm_aad_inject(&c->gcm, pkt, (size_t)(enc - pkt));
	br_gcm_flip(&c->gcm);
	br_gcm_run(&c->gcm, 0, enc, (size_t)(tag - enc));
	return br_gcm_check_tag(&c->gcm, tag);
}

static void encrypt_aes_gcm(const qcipher_class **vt, uint64_t pktnum, const void *iv, uint8_t *pkt, uint8_t *enc, uint8_t *tag) {
	qcipher_aes_gcm *c = (qcipher_aes_gcm*)vt;
	uint8_t nonce[12];
	get_nonce_12(nonce, pktnum, iv);
	br_gcm_reset(&c->gcm, nonce, sizeof(nonce));
	br_gcm_aad_inject(&c->gcm, pkt, (size_t)(enc - pkt));
	br_gcm_flip(&c->gcm);
	br_gcm_run(&c->gcm, 1, enc, (size_t)(tag - enc));
	br_gcm_get_tag(&c->gcm, tag);
}

const qcipher_class TLS_AES_128_GCM_SHA256 = {
	0x1301,
	128 / 8, // key size
	12,      // IV size
	16,      // tag size
	&br_sha256_vtable,
	&init_aes_128_gcm_sha256,
	&protect_aes_gcm,
	&decrypt_aes_gcm,
	&encrypt_aes_gcm,
};

const qcipher_class TLS_AES_256_GCM_SHA384 = {
	0x1302,
	256 / 8, // key size
	12,      // IV size
	16,      // tag size
	&br_sha384_vtable,
	&init_aes_256_gcm_sha384,
	&protect_aes_gcm,
	&decrypt_aes_gcm,
	&encrypt_aes_gcm,
};

static void init_aes_128_ccm_sha256(const qcipher_class **vt, const void *pn_key, const void *data_key) {
	qcipher_aes_ccm *c = (qcipher_aes_ccm*)vt;
	c->vtable = &TLS_AES_128_CCM_SHA256;
	const br_block_ctr_class *ctr = br_aes_x86ni_ctr_get_vtable();
	if (!ctr) {
		ctr = &br_aes_big_ctr_vtable;
	}
	ctr->init(&c->pn.vtable, pn_key, (*vt)->key_size);

	const br_block_ctrcbc_class *cbc = br_aes_x86ni_ctrcbc_get_vtable();
	if (!cbc) {
		cbc = &br_aes_big_ctrcbc_vtable;
	}
	cbc->init(&c->data.vtable, data_key, (*vt)->key_size);
	br_ccm_init(&c->ccm, &c->data.vtable);
}

static void protect_aes_ccm(const qcipher_class **vt, void *pktnum, size_t num_sz, size_t pay_sz) {
	// bearssl takes the AES CTR IV as 12B IV | 4B counter
	// QUIC wants to provide a 16B IV so we need to break them apart again from the sample
	qcipher_aes_ccm *c = (qcipher_aes_ccm*)vt;
	char *sample = (char*)pktnum + ((pay_sz < 20) ? (pay_sz - 16) : 4);
	c->pn.vtable->run(&c->pn.vtable, sample, big_32((char*)sample + 12), pktnum, num_sz);
}

#define CCM_TAG_LEN 16

static uint32_t decrypt_aes_ccm(const qcipher_class **vt, uint64_t pktnum, const void *iv, const uint8_t *pkt, const uint8_t *enc, const uint8_t *tag) {
	qcipher_aes_ccm *c = (qcipher_aes_ccm*)vt;
	size_t aad_len = (size_t)(enc - pkt);
	size_t data_len = (size_t)(tag - enc);
	uint8_t nonce[12];
	get_nonce_12(nonce, pktnum, iv);
	br_ccm_reset(&c->ccm, nonce, sizeof(nonce), aad_len, data_len, CCM_TAG_LEN);
	br_ccm_aad_inject(&c->ccm, pkt, aad_len);
	br_ccm_flip(&c->ccm);
	br_ccm_run(&c->ccm, 0, enc, data_len);
	return br_ccm_check_tag(&c->ccm, tag);
}

static void encrypt_aes_ccm(const qcipher_class **vt, uint64_t pktnum, const void *iv, uint8_t *pkt, uint8_t *enc, uint8_t *tag) {
	qcipher_aes_ccm *c = (qcipher_aes_ccm*)vt;
	size_t aad_len = (size_t)(enc - pkt);
	size_t data_len = (size_t)(tag - enc);
	uint8_t nonce[12];
	get_nonce_12(nonce, pktnum, iv);
	br_ccm_reset(&c->ccm, nonce, sizeof(nonce), aad_len, data_len, CCM_TAG_LEN);
	br_ccm_aad_inject(&c->ccm, pkt, aad_len);
	br_ccm_flip(&c->ccm);
	br_ccm_run(&c->ccm, 1, enc, data_len);
	br_ccm_get_tag(&c->ccm, tag);
}

const qcipher_class TLS_AES_128_CCM_SHA256 = {
	0x1304,
	128 / 8, // key size
	12,      // IV size
	CCM_TAG_LEN,      // tag size
	&br_sha256_vtable,
	&init_aes_128_ccm_sha256,
	&protect_aes_ccm,
	&decrypt_aes_ccm,
	&encrypt_aes_ccm,
};

static void init_chacha20_poly1305_sha256(const qcipher_class **vt, const void *pn_key, const void *data_key) {
	qcipher_chacha20 *c = (qcipher_chacha20*)vt;
	c->vtable = &TLS_CHACHA20_POLY1305_SHA256;
	c->pn_key = pn_key;
	c->data_key = data_key;
}

static br_chacha20_run get_chacha20(void) {
	br_chacha20_run fn = br_chacha20_sse2_get();
	return fn ? fn : &br_chacha20_ct_run;
}

static br_poly1305_run get_poly1305(void) {
	br_poly1305_run fn = br_poly1305_ctmulq_get();
	return fn ? fn : &br_poly1305_ctmul32_run;
}

static void protect_chacha20(const qcipher_class **vt, void *pktnum, size_t num_sz, size_t pay_sz) {
	qcipher_chacha20 *c = (qcipher_chacha20*)vt;
	br_chacha20_run fn = get_chacha20();
	char *sample = (char*)pktnum + ((pay_sz < 20) ? (pay_sz - 16) : 4);
	uint32_t cc = little_32(sample);
	fn(c->pn_key, (char*)sample + 4, cc, pktnum, num_sz);
}

static inline uint32_t
EQ0(int32_t x) {
	uint32_t q;

	q = (uint32_t)x;
	return ~(q | -q) >> 31;
}

static uint32_t decrypt_chacha20(const qcipher_class **vt, uint64_t pktnum, const void *iv, const uint8_t *pkt, const uint8_t *enc, const uint8_t *tag) {
	qcipher_chacha20 *c = (qcipher_chacha20*)vt;
	uint8_t nonce[12];
	get_nonce_12(nonce, pktnum, iv);
	uint8_t tmp[16];
	br_poly1305_run poly1305 = get_poly1305();
	poly1305(c->data_key, nonce, enc, (size_t)(tag-enc), pkt, (size_t)(enc-pkt), tmp, get_chacha20(), 0);
	// constant time compare the tags
	uint32_t z = 0;
	for (size_t u = 0; u < 16; u++) {
		z |= tmp[u] ^ ((uint8_t*)tag)[u];
	}
	return EQ0(z);
}

static void encrypt_chacha20(const qcipher_class **vt, uint64_t pktnum, const void *iv, uint8_t *pkt, uint8_t *enc, uint8_t *tag) {
	qcipher_chacha20 *c = (qcipher_chacha20*)vt;
	uint8_t nonce[12];
	get_nonce_12(nonce, pktnum, iv);
	br_poly1305_run poly1305 = get_poly1305();
	poly1305(c->data_key, nonce, enc, (size_t)(tag-enc), pkt, (size_t)(enc-pkt), tag, get_chacha20(), 1);
}

const qcipher_class TLS_CHACHA20_POLY1305_SHA256 = {
	0x1303,
	256 / 8, // key size
	12, // iv size
	16, // tag size
	&init_chacha20_poly1305_sha256,
	&protect_chacha20,
	&decrypt_chacha20,
	&encrypt_chacha20,
};

// Prefer Chacha20 over AES (faster, smaller code)
// Prefer AES-128 over 256 (AES-128 is already strong enough and AES-256 is 40% more expensive)
// Prefer GCM over CCM

const qcipher_class *TLS_DEFAULT_CIPHERS[] = {
	&TLS_CHACHA20_POLY1305_SHA256,
	&TLS_AES_128_GCM_SHA256,
	&TLS_AES_256_GCM_SHA384,
	&TLS_AES_128_CCM_SHA256,
	NULL,
};





