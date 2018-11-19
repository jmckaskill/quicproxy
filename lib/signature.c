#include "signature.h"
#include "cipher.h"
#include "crypto.h"

// fake rsa curves to allow for a signatures bitset
#define RSA_PKCS1_SHA256_CURVE 63
#define RSA_PKCS1_SHA384_CURVE 62
#define RSA_PKCS1_SHA512_CURVE 61

static int verify_rsa_pkcs1(const qsignature_class *c, const br_x509_pkey *pk, const br_ec_impl *ec, const void *text, size_t text_len, const void *sig, size_t sig_len) {
	(void)ec;
	if (pk->key_type != BR_KEYTYPE_RSA) {
		return -1;
	}

	br_rsa_pkcs1_vrfy fn = br_rsa_i62_pkcs1_vrfy_get();
	if (!fn) {
		fn = &br_rsa_i31_pkcs1_vrfy;
	}

	uint8_t hash1[QUIC_MAX_HASH_SIZE];
	uint8_t hash2[QUIC_MAX_HASH_SIZE];
	if (!fn(sig, sig_len, digest_size(c->hash), &pk->key.rsa, hash1)) {
		return -1;
	}
	br_hash_compat_context h;
	c->hash->init(&h.vtable);
	c->hash->update(&h.vtable, text, text_len);
	c->hash->out(&h.vtable, hash2);
	return memcmp(hash1, hash2, digest_size(c->hash));
}

const qsignature_class TLS_RSA_PKCS1_SHA256 = {
	0x0401,
	&br_sha256_vtable,
	BR_HASH_OID_SHA256,
	NULL,
	RSA_PKCS1_SHA256_CURVE,
	&verify_rsa_pkcs1,
};

const qsignature_class TLS_RSA_PKCS1_SHA384 = {
	0x0501,
	&br_sha384_vtable,
	BR_HASH_OID_SHA384,
	NULL,
	RSA_PKCS1_SHA384_CURVE,
	&verify_rsa_pkcs1,
};

const qsignature_class TLS_RSA_PKCS1_SHA512 = {
	0x0601,
	&br_sha512_vtable,
	BR_HASH_OID_SHA512,
	NULL,
	RSA_PKCS1_SHA512_CURVE,
	&verify_rsa_pkcs1,
};

static int verify_ecdsa(const qsignature_class *c, const br_x509_pkey *pk, const void *text, size_t text_len, const void *sig, size_t sig_len) {
	if (pk->key_type != BR_KEYTYPE_EC || pk->key.ec.curve != c->curve) {
		return -1;
	}

	uint8_t hash[QUIC_MAX_HASH_SIZE];
	br_hash_compat_context h;
	c->hash->init(&h.vtable);
	c->hash->update(&h.vtable, text, text_len);
	c->hash->out(&h.vtable, hash);
	br_ecdsa_vrfy fn = br_ecdsa_vrfy_raw_get_default();
	return fn(c->ec, hash, digest_size(c->hash), &pk->key.ec, sig, sig_len) != 1;
}

const qsignature_class TLS_ECDSA_SECP256R1_SHA256 = {
	0x0403,
	&br_sha256_vtable,
	NULL,
	&br_ec_prime_i31,
	BR_EC_secp256r1,
	&verify_ecdsa,
};

const qsignature_class TLS_ECDSA_SECP384R1_SHA384 = {
	0x0503,
	&br_sha384_vtable,
	NULL,
	&br_ec_prime_i31,
	BR_EC_secp384r1,
	&verify_ecdsa,
};

const qsignature_class TLS_ECDSA_SECP521R1_SHA512 = {
	0x0603,
	&br_sha512_vtable,
	NULL,
	&br_ec_prime_i31,
	BR_EC_secp521r1,
	&verify_ecdsa,
};


const qsignature_class *TLS_DEFAULT_SIGNATURES[] = {
	&TLS_ECDSA_SECP256R1_SHA256,
	&TLS_ECDSA_SECP384R1_SHA384,
	&TLS_ECDSA_SECP521R1_SHA512,
	&TLS_RSA_PKCS1_SHA256,
	&TLS_RSA_PKCS1_SHA512,
	&TLS_RSA_PKCS1_SHA384,
	NULL,
};

struct signer_common {
	const qsigner_class **c;
	const br_x509_certificate *certs;
	size_t num_certs;
};

const br_x509_certificate *get_cert(const qsigner_class **c, size_t idx) {
	struct signer_common *s = (struct signer_common*) c;
	return (idx > s->num_certs) ? NULL : &s->certs[idx];
}

static const qsignature_class *get_rsa_pkcs1_type(const qsigner_class **c, size_t idx) {
	qsigner_rsa_pkcs1 *s = (qsigner_rsa_pkcs1*)c;
	return s->sigs[idx];
}

static int sign_rsa_pkcs1(const qsigner_class **c, const qsignature_class *sig, const void *text, size_t text_len, void *sig) {
	qsigner_rsa_pkcs1 *s = (qsigner_rsa_pkcs1*)c;

	uint8_t hash[QUIC_MAX_HASH_SIZE];
	br_hash_compat_context h;
	sig->hash->init(&h.vtable);
	sig->hash->update(&h.vtable, text, text_len);
	sig->hash->out(&h.vtable, hash);

	br_rsa_pkcs1_sign fn = br_rsa_i62_pkcs1_sign_get();
	if (!fn) {
		fn = &br_rsa_i31_pkcs1_sign;
	}
	if (!fn(sig->hash_oid, hash, digest_size(sig->hash), s->sk, sig)) {
		return -1;
	}
	return (s->sk->n_bitlen + 7) / 8;
}

int qsigner_rsa_pkcs1_init(qsigner_rsa_pkcs1 *s, const qsignature_class *const *sigs, const br_rsa_private_key *sk, const br_x509_certificate *certs, size_t num) {
	if ((sk->n_bitlen + 7) / 8 > QUIC_MAX_SIG_SIZE) {
		return -1;
	}
	s->vtable = &TLS_RSA_PKCS1_signer;
	s->certs = certs;
	s->num_certs = num;
	s->sigs = sigs;
	s->sk = sk;
	return 0;
}

const qsigner_class TLS_RSA_PKCS1_signer = {
	&get_rsa_pkcs1_type,
	&get_cert,
	&sign_rsa_pkcs1,
};

static const qsignature_class *ecdsa_type(const qsigner_class **c, size_t idx) {
	qsigner_ecdsa *s = (qsigner_ecdsa*)c;
	return idx ? NULL : s->sig;
}

static int sign_ecdsa(const qsigner_class **c, const qsignature_class *sig, const void *text, size_t text_len, void *sig) {
	qsigner_ecdsa *s = (qsigner_ecdsa*)c;
	(void)sig;

	uint8_t hash[QUIC_MAX_HASH_SIZE];
	br_hash_compat_context h;
	s->sig->hash->init(&h.vtable);
	s->sig->hash->update(&h.vtable, text, text_len);
	s->sig->hash->out(&h.vtable, hash);

	br_ecdsa_sign fn = br_ecdsa_sign_raw_get_default();
	size_t ret = fn(s->sig->ec, s->sig->hash, hash, s->sk, sig);
	return ret ? (int)ret : -1;
}

static const qsignature_class *find_signature(const qsignature_class *const *s, int curve) {
	while (*s) {
		if ((*s)->curve == curve) {
			return *s;
		}
	}
	return NULL;
}

int qsigner_ecdsa_init(qsigner_ecdsa *s, const qsignature_class *const *signatures, const br_ec_private_key *sk, const br_x509_certificate *certs, size_t num) {
	s->sig = find_signature(signatures, sk->curve);
	if (!s->sig) {
		return -1;
	}
	s->vtable = &TLS_ECDSA_signer;
	s->certs = certs;
	s->num_certs = num;
	s->sk = sk;
	return 0;
}

const qsigner_class TLS_ECDSA_signer = {
	&ecdsa_type,
	&get_cert,
	&sign_ecdsa,
};











