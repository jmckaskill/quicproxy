#include "kdf.h"


static void hkdf_extract(const br_hash_class *digest, const void *salt, size_t saltsz, const void *ikm, size_t ikmsz, void *out) {
	br_hmac_key_context kc;
	br_hmac_context hmac;
	br_hmac_key_init(&kc, digest, salt, saltsz);
	br_hmac_init(&hmac, &kc, 0);
	br_hmac_update(&hmac, ikm, ikmsz);
	br_hmac_out(&hmac, out);
}

static void hkdf_expand(const br_hash_class *digest, const void *secret, const void *info, size_t infosz, void *out, size_t outsz) {
	br_hmac_key_context kc;
	br_hmac_context hmac;
	assert(outsz <= digest_size(digest));
	br_hmac_key_init(&kc, digest, secret, digest_size(digest));
	br_hmac_init(&hmac, &kc, outsz);
	br_hmac_update(&hmac, info, infosz);
	uint8_t chunk_num = 1;
	br_hmac_update(&hmac, &chunk_num, 1);
	br_hmac_out(&hmac, out);
}

static void hkdf_expand_label(const br_hash_class *digest, const void *secret, const char *label, const void *context, size_t ctxsz, void *out, size_t outsz) {
	uint8_t hk_label[2 + 1 + 32 + 1 + 32], *p = hk_label;
	size_t labelsz = strlen(label);
	assert(labelsz <= 32);
	assert(ctxsz <= 32);
	assert(outsz <= UINT16_MAX);
	p = write_big_16(p, (uint16_t)outsz);
	*(p++) = (uint8_t)labelsz;
	p = append(p, label, labelsz);
	*(p++) = (uint8_t)ctxsz;
	p = append(p, context, ctxsz);
	hkdf_expand(digest, secret, hk_label, p - hk_label, out, outsz);
}

static void init_keyset(qkeyset_t *k, const qcipher_class *cipher) {
	hkdf_expand_label(cipher->hash, k->secret, "quic key", NULL, 0, k->data_key, cipher->key_size);
	hkdf_expand_label(cipher->hash, k->secret, "quic pn", NULL, 0, k->pn_key, cipher->key_size);
	hkdf_expand_label(cipher->hash, k->secret, "quic iv", NULL, 0, k->data_iv, cipher->iv_size);
	cipher->init(&k->u.vtable, k->pn_key, k->data_key);
}

static const uint8_t initial_salt[] = {
	0x9c, 0x10, 0x8f, 0x98, 0x52, 0x0a, 0x5c, 0x5c,
	0x32, 0x96, 0x8e, 0x95, 0x0e, 0x8a, 0x2c, 0x5f,
	0xe0, 0x6d, 0x6c, 0x38,
};

void generate_initial_secrets(const uint8_t *id, qkeyset_t *client, qkeyset_t *server) {
	uint8_t initial_secret[br_sha256_SIZE];
	hkdf_extract(&br_sha256_vtable, initial_salt, sizeof(initial_salt), id+1, id[0], initial_secret);
	if (client) {
		hkdf_expand_label(&br_sha256_vtable, initial_secret, "quic client in", NULL, 0, client->secret, br_sha256_SIZE);
		init_keyset(client, &TLS_AES_128_GCM_SHA256);
	}
	if (server) {
		hkdf_expand_label(&br_sha256_vtable, initial_secret, "quic server in", NULL, 0, server->secret, br_sha256_SIZE);
		init_keyset(server, &TLS_AES_128_GCM_SHA256);
	}
}

int generate_handshake_secrets(const qcipher_class *cipher, const br_hash_class *const *msgs, const br_ec_public_key *pk, const br_ec_private_key *sk, qkeyset_t *client, qkeyset_t *server, uint8_t *master_secret) {
	size_t hash_len = digest_size(*msgs);
	uint8_t msg_hash[QUIC_MAX_HASH_SIZE];
	(*msgs)->out(msgs, msg_hash);

	const br_ec_impl *ec = br_ec_get_default();
	uint8_t ikm[BR_EC_KBUF_PUB_MAX_SIZE];
	memcpy(ikm, pk->q, pk->qlen);
	if (!ec->mul(ikm, pk->qlen, sk->x, sk->xlen, pk->curve)) {
		return -1;
	}
	size_t xlen, xoff = ec->xoff(pk->curve, &xlen);
	if (xoff + xlen > pk->qlen) {
		return -1;
	}

	uint8_t early_secret[QUIC_MAX_SECRET_SIZE];
	uint8_t early_derived[QUIC_MAX_SECRET_SIZE];
	hkdf_extract(*msgs, NULL, 0, NULL, 0, early_secret);
	hkdf_expand_label(*msgs, early_secret, "quic derived", NULL, 0, early_derived, hash_len);

	uint8_t hs_secret[QUIC_MAX_SECRET_SIZE];
	hkdf_extract(*msgs, early_derived, hash_len, ikm + xoff, xlen, hs_secret);
	hkdf_expand_label(*msgs, hs_secret, "quic c hs traffic", msg_hash, hash_len, client->secret, hash_len);
	hkdf_expand_label(*msgs, hs_secret, "quic s hs traffic", msg_hash, hash_len, server->secret, hash_len);

	uint8_t derived[QUIC_MAX_SECRET_SIZE];
	hkdf_expand_label(*msgs, hs_secret, "quic derived", NULL, 0, derived, hash_len);
	hkdf_extract(*msgs, derived, hash_len, NULL, 0, master_secret);

	init_keyset(client, cipher);
	init_keyset(server, cipher);
	return 0;
}

void generate_protected_secrets(const qcipher_class *cipher, const br_hash_class *const *msgs, const uint8_t *master_secret, qkeyset_t *client, qkeyset_t *server) {
	size_t hash_len = digest_size(*msgs);
	uint8_t msg_hash[QUIC_MAX_HASH_SIZE];
	(*msgs)->out(msgs, msg_hash);

	hkdf_expand_label(*msgs, master_secret, "quic c ap traffic", msg_hash, hash_len, client->secret, hash_len);
	hkdf_expand_label(*msgs, master_secret, "quic s ap traffic", msg_hash, hash_len, server->secret, hash_len);

	init_keyset(client, cipher);
	init_keyset(server, cipher);
}

static const char server_context[] = "TLS 1.3, server CertificateVerify";
static const char client_context[] = "TLS 1.3, client CertificateVerify";

size_t generate_cert_verify(const br_hash_class *digest, bool is_client, const uint8_t *msg_hash, uint8_t *out) {
	assert(64 + sizeof(server_context) + digest_size(digest) <= QUIC_MAX_CERT_VERIFY_SIZE);
	uint8_t *start = out;
	memset(out, 0x20, 64);
	out += 64;
	if (is_client) {
		out = append(out, client_context, sizeof(client_context));
	} else {
		out = append(out, server_context, sizeof(server_context));
	}
	out = append(out, msg_hash, digest_size(digest));
	return out - start;
}

size_t generate_finish_verify(qkeyset_t *k, const uint8_t *msg_hash, uint8_t *out) {
	const br_hash_class *digest = k->u.vtable->hash;
	size_t hash_len = digest_size(digest);
	uint8_t finished_key[QUIC_MAX_HASH_SIZE];
	hkdf_expand_label(digest, k->secret, "quic finished", NULL, 0, finished_key, hash_len);
	br_hmac_key_context kc;
	br_hmac_context ctx;
	br_hmac_key_init(&kc, digest, finished_key, hash_len);
	br_hmac_init(&ctx, &kc, 0);
	br_hmac_update(&ctx, msg_hash, hash_len);
	br_hmac_out(&ctx, out);
	return hash_len;
}

