#include "cipher.h"
#include "kdf.h"
#include <cutils/endian.h>

static void expand_data_key(const br_hash_class *digest, const void *traffic, void *key, size_t key_size) {
	hkdf_expand_label(key, key_size, digest, traffic, "quic key", NULL);
}

static void expand_pn_key(const br_hash_class *digest, const void *traffic, void *key, size_t key_size) {
	hkdf_expand_label(key, key_size, digest, traffic, "quic pn", NULL);
}

static void expand_data_iv(const br_hash_class *digest, const void *traffic, void *iv, size_t iv_size) {
	hkdf_expand_label(iv, iv_size, digest, traffic, "quic iv", NULL);
}

const qcipher_class *find_cipher(const qcipher_class *const *s, uint16_t code) {
	while (*s) {
		if ((*s)->code == code) {
			return *s;
		}
		s++;
	}
	return NULL;
}

static void get_nonce_12(uint8_t *nonce, uint64_t pktnum, const void *iv) {
	write_big_32(nonce, 0);
	write_big_64(nonce + 4, pktnum);
	for (int i = 0; i < 12; i++) {
		nonce[i] ^= ((uint8_t*)iv)[i];
	}
}

static void init_aes_gcm(qcipher_aes_gcm *c, const br_hash_class *digest, const void *traffic, size_t key_size) {
	br_ghash gh = br_ghash_pclmul_get();
	if (!gh) {
		gh = &br_ghash_ctmul;
	}
	const br_block_ctr_class *b = br_aes_x86ni_ctr_get_vtable();
	if (!b) {
		b = &br_aes_big_ctr_vtable;
	}
	uint8_t data_key[32], pn_key[32];
	expand_data_key(digest, traffic, data_key, key_size);
	expand_pn_key(digest, traffic, pn_key, key_size);
	expand_data_iv(digest, traffic, c->data_iv, sizeof(c->data_iv));
	b->init(&c->pn.vtable, pn_key, key_size);
	b->init(&c->data.vtable, data_key, key_size);
	br_gcm_init(&c->gcm, &c->data.vtable, gh);
}

void init_aes_128_gcm(qcipher_aes_gcm *c, const void *traffic) {
	c->vtable = &TLS_AES_128_GCM_SHA256;
	init_aes_gcm(c, &br_sha256_vtable, traffic, 16);
}

static void init_aes_256_gcm_sha384(const qcipher_class **vt, const void *traffic) {
	qcipher_aes_gcm *c = (qcipher_aes_gcm*)vt;
	c->vtable = &TLS_AES_256_GCM_SHA384;
	init_aes_gcm(c, &br_sha384_vtable, traffic, 32);
}

static void protect_aes_gcm(const qcipher_class **vt, void *pktnum, size_t num_sz, size_t pay_sz) {
	// bearssl takes the AES CTR IV as 12B IV | 4B counter
	// QUIC wants to provide a 16B IV so we need to break them apart again from the sample
	qcipher_aes_gcm *c = (qcipher_aes_gcm*)vt;
	char *sample = (char*)pktnum + ((pay_sz < 20) ? (pay_sz - 16) : 4);
	c->pn.vtable->run(&c->pn.vtable, sample, big_32((char*)sample + 12), pktnum, num_sz);
}

static int decrypt_aes_gcm(const qcipher_class **vt, uint64_t pktnum, const void *aad, size_t aad_len, uint8_t *enc, uint8_t *tag) {
	qcipher_aes_gcm *c = (qcipher_aes_gcm*)vt;
	uint8_t nonce[12];
	get_nonce_12(nonce, pktnum, c->data_iv);
	br_gcm_reset(&c->gcm, nonce, sizeof(nonce));
	br_gcm_aad_inject(&c->gcm, aad, aad_len);
	br_gcm_flip(&c->gcm);
	br_gcm_run(&c->gcm, 0, enc, (size_t)(tag - enc));
	return br_gcm_check_tag(&c->gcm, tag) != 1;
}

static void encrypt_aes_gcm(const qcipher_class **vt, uint64_t pktnum, const void *aad, size_t aad_len, uint8_t *enc, uint8_t *tag) {
	qcipher_aes_gcm *c = (qcipher_aes_gcm*)vt;
	uint8_t nonce[12];
	get_nonce_12(nonce, pktnum, c->data_iv);
	br_gcm_reset(&c->gcm, nonce, sizeof(nonce));
	br_gcm_aad_inject(&c->gcm, aad, aad_len);
	br_gcm_flip(&c->gcm);
	br_gcm_run(&c->gcm, 1, enc, (size_t)(tag - enc));
	br_gcm_get_tag(&c->gcm, tag);
}

const qcipher_class TLS_AES_128_GCM_SHA256 = {
	0x1301,
	&br_sha256_vtable,
	(void(*)(const qcipher_class**,const void*))&init_aes_128_gcm,
	&protect_aes_gcm,
	&decrypt_aes_gcm,
	&encrypt_aes_gcm,
};

const qcipher_class TLS_AES_256_GCM_SHA384 = {
	0x1302,
	&br_sha384_vtable,
	&init_aes_256_gcm_sha384,
	&protect_aes_gcm,
	&decrypt_aes_gcm,
	&encrypt_aes_gcm,
};

static void init_aes_128_ccm_sha256(const qcipher_class **vt, const void *traffic) {
	qcipher_aes_ccm *c = (qcipher_aes_ccm*)vt;
	c->vtable = &TLS_AES_128_CCM_SHA256;

	uint8_t pn_key[16];
	expand_pn_key(&br_sha256_vtable, traffic, pn_key, sizeof(pn_key));
	const br_block_ctr_class *ctr = br_aes_x86ni_ctr_get_vtable();
	if (!ctr) {
		ctr = &br_aes_big_ctr_vtable;
	}
	ctr->init(&c->pn.vtable, pn_key, sizeof(pn_key));

	uint8_t data_key[16];
	expand_data_key(&br_sha256_vtable, traffic, data_key, sizeof(data_key));
	const br_block_ctrcbc_class *cbc = br_aes_x86ni_ctrcbc_get_vtable();
	if (!cbc) {
		cbc = &br_aes_big_ctrcbc_vtable;
	}
	cbc->init(&c->data.vtable, data_key, sizeof(data_key));
	br_ccm_init(&c->ccm, &c->data.vtable);

	expand_data_iv(&br_sha256_vtable, traffic, c->data_iv, sizeof(c->data_iv));
}

static void protect_aes_ccm(const qcipher_class **vt, void *pktnum, size_t num_sz, size_t pay_sz) {
	// bearssl takes the AES CTR IV as 12B IV | 4B counter
	// QUIC wants to provide a 16B IV so we need to break them apart again from the sample
	qcipher_aes_ccm *c = (qcipher_aes_ccm*)vt;
	char *sample = (char*)pktnum + ((pay_sz < 20) ? (pay_sz - 16) : 4);
	c->pn.vtable->run(&c->pn.vtable, sample, big_32((char*)sample + 12), pktnum, num_sz);
}

#define CCM_TAG_LEN 16

static int decrypt_aes_ccm(const qcipher_class **vt, uint64_t pktnum, const void *aad, size_t aad_len, uint8_t *enc, uint8_t *tag) {
	qcipher_aes_ccm *c = (qcipher_aes_ccm*)vt;
	size_t data_len = (size_t)(tag - enc);
	uint8_t nonce[12];
	get_nonce_12(nonce, pktnum, c->data_iv);
	br_ccm_reset(&c->ccm, nonce, sizeof(nonce), aad_len, data_len, CCM_TAG_LEN);
	br_ccm_aad_inject(&c->ccm, aad, aad_len);
	br_ccm_flip(&c->ccm);
	br_ccm_run(&c->ccm, 0, enc, data_len);
	return br_ccm_check_tag(&c->ccm, tag) != 1;
}

static void encrypt_aes_ccm(const qcipher_class **vt, uint64_t pktnum, const void *aad, size_t aad_len, uint8_t *enc, uint8_t *tag) {
	qcipher_aes_ccm *c = (qcipher_aes_ccm*)vt;
	size_t data_len = (size_t)(tag - enc);
	uint8_t nonce[12];
	get_nonce_12(nonce, pktnum, c->data_iv);
	br_ccm_reset(&c->ccm, nonce, sizeof(nonce), aad_len, data_len, CCM_TAG_LEN);
	br_ccm_aad_inject(&c->ccm, aad, aad_len);
	br_ccm_flip(&c->ccm);
	br_ccm_run(&c->ccm, 1, enc, data_len);
	br_ccm_get_tag(&c->ccm, tag);
}

const qcipher_class TLS_AES_128_CCM_SHA256 = {
	0x1304,
	&br_sha256_vtable,
	&init_aes_128_ccm_sha256,
	&protect_aes_ccm,
	&decrypt_aes_ccm,
	&encrypt_aes_ccm,
};

static void init_chacha20_poly1305_sha256(const qcipher_class **vt, const void *traffic) {
	qcipher_chacha20 *c = (qcipher_chacha20*)vt;
	c->vtable = &TLS_CHACHA20_POLY1305_SHA256;
	expand_data_iv(&br_sha256_vtable, traffic, c->data_iv, sizeof(c->data_iv));
	expand_data_key(&br_sha256_vtable, traffic, c->data_key, sizeof(c->data_key));
	expand_pn_key(&br_sha256_vtable, traffic, c->pn_key, sizeof(c->pn_key));
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

static uint32_t EQ0(int32_t x) {
	uint32_t q = (uint32_t)x;
	return ~(q | (0-q)) >> 31;
}

static int decrypt_chacha20(const qcipher_class **vt, uint64_t pktnum, const void *aad, size_t aad_len, uint8_t *enc, uint8_t *tag) {
	qcipher_chacha20 *c = (qcipher_chacha20*)vt;
	uint8_t nonce[12];
	get_nonce_12(nonce, pktnum, c->data_iv);
	uint8_t tmp[16];
	br_poly1305_run poly1305 = get_poly1305();
	poly1305(c->data_key, nonce, enc, (size_t)(tag-enc), aad, aad_len, tmp, get_chacha20(), 0);
	// constant time compare the tags
	uint32_t z = 0;
	for (size_t u = 0; u < 16; u++) {
		z |= tmp[u] ^ ((uint8_t*)tag)[u];
	}
	return EQ0(z) != 1;
}

static void encrypt_chacha20(const qcipher_class **vt, uint64_t pktnum, const void *aad, size_t aad_len, uint8_t *enc, uint8_t *tag) {
	qcipher_chacha20 *c = (qcipher_chacha20*)vt;
	uint8_t nonce[12];
	get_nonce_12(nonce, pktnum, c->data_iv);
	br_poly1305_run poly1305 = get_poly1305();
	poly1305(c->data_key, nonce, enc, (size_t)(tag-enc), aad, aad_len, tag, get_chacha20(), 1);
}

const qcipher_class TLS_CHACHA20_POLY1305_SHA256 = {
	0x1303,
	&br_sha256_vtable,
	&init_chacha20_poly1305_sha256,
	&protect_chacha20,
	&decrypt_chacha20,
	&encrypt_chacha20,
};

// Prefer Chacha20 over AES (faster, smaller code)
// Prefer AES-128 over 256 (AES-128 is already strong enough and AES-256 is 40% more expensive)
// Prefer GCM over CCM

const qcipher_class *TLS_DEFAULT_CIPHERS[] = {
	&TLS_AES_128_GCM_SHA256,
	&TLS_CHACHA20_POLY1305_SHA256,
	&TLS_AES_256_GCM_SHA384,
	&TLS_AES_128_CCM_SHA256,
	NULL,
};





