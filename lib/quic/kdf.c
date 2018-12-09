#include "kdf.h"
#include <cutils/log.h>
#include <cutils/endian.h>


static void hkdf_extract(void *out, const br_hash_class *digest, const void *salt, size_t saltsz, const void *ikm, size_t ikmsz) {
	br_hmac_key_context kc;
	br_hmac_context hmac;
	br_hmac_key_init(&kc, digest, salt, saltsz);
	br_hmac_init(&hmac, &kc, 0);
	br_hmac_update(&hmac, ikm, ikmsz);
	br_hmac_out(&hmac, out);
}

static void hkdf_expand(void *out, size_t outsz, const br_hash_class *digest, const void *secret, const void *info, size_t infosz) {
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

void hkdf_expand_label(void *out, size_t outsz, const br_hash_class *digest, const void *secret, const char *label, const void *msg_hash) {
	uint8_t hk_label[2 + 1 + 32 + 1 + 32], *p = hk_label;
	size_t labelsz = strlen(label);
	assert(labelsz <= 32);
	assert(outsz <= UINT16_MAX);
	p = write_big_16(p, (uint16_t)outsz);
	*(p++) = (uint8_t)labelsz;
	p = append_mem(p, label, labelsz);
	if (msg_hash) {
		size_t hash_len = digest_size(digest);
		*(p++) = (uint8_t)hash_len;
		p = append_mem(p, msg_hash, hash_len);
	} else {
		*(p++) = 0;
	}
	hkdf_expand(out, outsz, digest, secret, hk_label, p - hk_label);
}

void derive_secret(void *derived, const br_hash_class *hash, const void *secret, const char *label, const void *msg_hash) {
	hkdf_expand_label(derived, digest_size(hash), hash, secret, label, msg_hash);
}

static const uint8_t initial_salt[] = {
	0x9c, 0x10, 0x8f, 0x98, 0x52, 0x0a, 0x5c, 0x5c,
	0x32, 0x96, 0x8e, 0x95, 0x0e, 0x8a, 0x2c, 0x5f,
	0xe0, 0x6d, 0x6c, 0x38,
};

void init_initial_cipher(qcipher_aes_gcm *k, int is_server, const void *server_id, size_t id_len) {
	uint8_t secret[br_sha256_SIZE];
	uint8_t traffic[br_sha256_SIZE];
	hkdf_extract(secret, &br_sha256_vtable, initial_salt, sizeof(initial_salt), server_id, id_len);
	derive_secret(traffic, &br_sha256_vtable, secret, is_server ? "quic server in" : "quic client in", NULL);
	init_aes_128_gcm(k, traffic);
}

int calc_handshake_secret(void *secret, const br_hash_class *digest, const void *msg_hash, const br_ec_public_key *pk, const br_ec_private_key *sk) {
	size_t hash_len = digest_size(digest);

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
	hkdf_extract(early_secret, digest, NULL, 0, NULL, 0);
	derive_secret(early_derived, digest, early_secret, "quic derived", NULL);
	hkdf_extract(secret, digest, early_derived, hash_len, ikm + xoff, xlen);
	return 0;
}

void calc_master_secret(void *master, const br_hash_class *digest, const void *handshake) {
	size_t hash_len = digest_size(digest);
	uint8_t derived[QUIC_MAX_SECRET_SIZE];
	derive_secret(derived, digest, handshake, "quic derived", NULL);
	hkdf_extract(master, digest, derived, hash_len, NULL, 0);
}

static const char server_context[] = "TLS 1.3, server CertificateVerify";
static const char client_context[] = "TLS 1.3, client CertificateVerify";

size_t calc_cert_verify(void *out, bool client, const br_hash_class *digest, const void *msg_hash) {
	size_t hash_len = digest_size(digest);
	size_t ret = 64 + sizeof(server_context) + hash_len;
	assert(64 + sizeof(server_context) + hash_len <= QUIC_MAX_CERT_VERIFY_SIZE);
	out = append_bytes(out, ' ', 64);
	out = append_mem(out, client ? client_context : server_context, sizeof(client_context));
	out = append_mem(out, msg_hash, hash_len);
	return ret;
}

void calc_finish_verify(void *out, const br_hash_class *digest, const void *msg_hash, const void *hs_traffic) {
	size_t hash_len = digest_size(digest);
	uint8_t key[QUIC_MAX_HASH_SIZE];
	derive_secret(key, digest, hs_traffic, "quic finished", NULL);
	br_hmac_key_context kc;
	br_hmac_context ctx;
	br_hmac_key_init(&kc, digest, key, hash_len);
	br_hmac_init(&ctx, &kc, 0);
	br_hmac_update(&ctx, msg_hash, hash_len);
	br_hmac_out(&ctx, out);
}

static void log_key(log_t *log, const char *label, const uint8_t *client_random, const uint8_t *secret, size_t len) {
	static const char hex[] = "0123456789abcdef";
	char sec_hex[2 * QUIC_MAX_HASH_SIZE + 1];
	char rand_hex[2 * QUIC_RANDOM_SIZE + 1];
	for (size_t i = 0; i < QUIC_RANDOM_SIZE; i++) {
		rand_hex[2 * i] = hex[client_random[i] >> 4];
		rand_hex[2 * i + 1] = hex[client_random[i] & 15];
	}
	rand_hex[2 * QUIC_RANDOM_SIZE] = 0;
	for (size_t i = 0; i < len; i++) {
		sec_hex[2 * i] = hex[secret[i] >> 4];
		sec_hex[2 * i + 1] = hex[secret[i] & 15];
	}
	sec_hex[2 * len] = 0;
	LOG(log, "%s %s %s\n", label, rand_hex, sec_hex);
}

void log_handshake(log_t *log, const  br_hash_class *digest, const void *client, const void *server, const void *client_random) {
	if (log) {
		size_t hash_len = digest_size(digest);
		log_key(log, "QUIC_CLIENT_HANDSHAKE_TRAFFIC_SECRET", (uint8_t*)client_random, (uint8_t*)client, hash_len);
		log_key(log, "QUIC_SERVER_HANDSHAKE_TRAFFIC_SECRET", (uint8_t*)client_random, (uint8_t*)server, hash_len);
	}
}

void log_protected(log_t *log, const br_hash_class *digest, const void *client, const void *server, const void *client_random) {
	if (log) {
		size_t hash_len = digest_size(digest);
		log_key(log, "QUIC_CLIENT_TRAFFIC_SECRET_0", (uint8_t*)client_random, (uint8_t*)client, hash_len);
		log_key(log, "QUIC_SERVER_TRAFFIC_SECRET_0", (uint8_t*)client_random, (uint8_t*)server, hash_len);
	}
}

