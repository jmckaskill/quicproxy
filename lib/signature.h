#pragma once
#include "bearssl_wrapper.h"

#define QUIC_MAX_SIG_SIZE 512 // allow for up to 4096 bit rsa keys

typedef struct qsignature_class qsignature_class;
struct qsignature_class {
	uint16_t algorithm;
	const br_hash_class *hash;
	const unsigned char *hash_oid;
	const br_ec_impl *ec;
	int curve;
	int(*verify)(const qsignature_class *c, const br_x509_pkey *pk, const void *text, size_t text_len, const void *sig, size_t sig_len);
};

extern const qsignature_class TLS_RSA_PKCS1_SHA256;
extern const qsignature_class TLS_RSA_PKCS1_SHA384;
extern const qsignature_class TLS_RSA_PKCS1_SHA512;
extern const qsignature_class TLS_ECDSA_SECP256R1_SHA256;
extern const qsignature_class TLS_ECDSA_SECP384R1_SHA384;
extern const qsignature_class TLS_ECDSA_SECP521R1_SHA512;

extern const qsignature_class *TLS_RSA_SIGNATURES[];
extern const qsignature_class *TLS_ECDSA_SIGNATURES[];
extern const qsignature_class *TLS_DEFAULT_SIGNATURES[];

typedef struct qsigner_class qsigner_class;
struct qsigner_class {
	const qsignature_class*(*get_type)(const qsigner_class *const*c, size_t idx);
	const br_x509_certificate*(*get_cert)(const qsigner_class *const*c, size_t idx);
	int(*sign)(const qsigner_class *const*c, const qsignature_class *type, const void *text, size_t text_len, void *out);
};

typedef struct qsigner_ecdsa qsigner_ecdsa;
struct qsigner_ecdsa {
	const qsigner_class *vtable;
	const br_x509_certificate *certs;
	size_t num_certs;
	const qsignature_class *sig;
	const br_ec_private_key *sk;
};

typedef struct qsigner_rsa_pkcs1 qsigner_rsa_pkcs1;
struct qsigner_rsa_pkcs1 {
	const qsigner_class *vtable;
	const br_x509_certificate *certs;
	size_t num_certs;
	const qsignature_class *const *sigs;
	const br_rsa_private_key *sk;
};

typedef union qsigner_compat qsigner_compat;
union qsigner_compat {
	const qsigner_class *vtable;
	qsigner_ecdsa ecdsa;
	qsigner_rsa_pkcs1 rsa_pkcs1;
};

extern const qsigner_class TLS_RSA_PKCS1_signer;
extern const qsigner_class TLS_ECDSA_signer;

int qsigner_rsa_pkcs1_init(qsigner_rsa_pkcs1 *s, const qsignature_class *const *sigs, const br_rsa_private_key *sk, const br_x509_certificate *certs, size_t num);
int qsigner_ecdsa_init(qsigner_ecdsa *s, const qsignature_class *const *sigs, const br_ec_private_key *sk, const br_x509_certificate *certs, size_t num);




