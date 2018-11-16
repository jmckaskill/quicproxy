#include "crypto.h"
#include "packets.h"
#include <cutils/endian.h>

static inline size_t
br_digest_size(const br_hash_class *digest_class) {
	return (size_t)(digest_class->desc >> BR_HASHDESC_OUT_OFF)
		& BR_HASHDESC_OUT_MASK;
}

void hkdf_extract(const br_hash_class *digest, const void *salt, size_t saltsz, const void *ikm, size_t ikmsz, void *out) {
	br_hmac_key_context kc;
	br_hmac_context hmac;
	br_hmac_key_init(&kc, digest, salt, saltsz);
	br_hmac_init(&hmac, &kc, 0);
	br_hmac_update(&hmac, ikm, ikmsz);
	br_hmac_out(&hmac, out);
}

void hkdf_expand(const br_hash_class *digest, size_t hash_len, const void *secret, const void *info, size_t infosz, void *out, size_t outsz) {
	br_hmac_key_context kc;
	br_hmac_context hmac;
	assert(outsz <= hash_len);
	br_hmac_key_init(&kc, digest, secret, hash_len);
	br_hmac_init(&hmac, &kc, outsz);
	br_hmac_update(&hmac, info, infosz);
	uint8_t chunk_num = 1;
	br_hmac_update(&hmac, &chunk_num, 1);
	br_hmac_out(&hmac, out);
}

void hkdf_expand_label(const br_hash_class *digest, size_t hash_len, const void *secret, const char *label, const void *context, size_t ctxsz, void *out, size_t outsz) {
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
	hkdf_expand(digest, hash_len, secret, hk_label, p - hk_label, out, outsz);
}

static void init_aes_ctr(br_aes_gen_ctr_keys *a, const void *key, size_t keysz) {
	if (br_aes_x86ni_ctr_get_vtable()) {
		br_aes_x86ni_ctr_init(&a->c_x86ni, key, keysz);
	} else {
		br_aes_big_ctr_init(&a->c_big, key, keysz);
	}
}

static void generate_keys(qkeyset_t *k) {
	hkdf_expand_label(k->digest, k->hash_len, k->secret, "quic key", NULL, 0, k->data_key, k->key_len);
	hkdf_expand_label(k->digest, k->hash_len, k->secret, "quic pn", NULL, 0, k->pn_key, k->key_len);
	hkdf_expand_label(k->digest, k->hash_len, k->secret, "quic iv", NULL, 0, k->data_iv, sizeof(k->data_iv));
	br_ghash gh = br_ghash_pclmul_get();
	if (!gh) {
		gh = &br_ghash_ctmul;
	}
	init_aes_ctr(&k->pn, k->pn_key, k->key_len);
	init_aes_ctr(&k->data, k->data_key, k->key_len);
	br_gcm_init(&k->gcm, &k->data.vtable, gh);
}

void reset_keyset(qkeyset_t *a, uint64_t pktnum) {
	// GCM IV is always 12 bytes
	uint8_t nonce[12] = { 0 };
	write_big_64(nonce + sizeof(nonce) - 8, pktnum);
	for (int i = 0; i < sizeof(nonce); i++) {
		nonce[i] ^= a->data_iv[i];
	}
	br_gcm_reset(&a->gcm, nonce, sizeof(nonce));
}

static const uint8_t initial_salt[] = {
	0x9c, 0x10, 0x8f, 0x98, 0x52, 0x0a, 0x5c, 0x5c,
	0x32, 0x96, 0x8e, 0x95, 0x0e, 0x8a, 0x2c, 0x5f,
	0xe0, 0x6d, 0x6c, 0x38,
};

void generate_initial_secrets(const qconnection_id_t *id, qkeyset_t *client, qkeyset_t *server) {
	uint8_t hash_len = 32;
	uint8_t initial_secret[br_sha256_SIZE];
	hkdf_extract(&br_sha256_vtable, initial_salt, sizeof(initial_salt), id->id, id->len, initial_secret);
	hkdf_expand_label(&br_sha256_vtable, hash_len, initial_secret, "quic client in", NULL, 0, client->secret, br_sha256_SIZE);
	hkdf_expand_label(&br_sha256_vtable, hash_len, initial_secret, "quic server in", NULL, 0, server->secret, br_sha256_SIZE);
	server->digest = client->digest = &br_sha256_vtable;
	server->hash_len = client->hash_len = hash_len;
	server->key_len = client->key_len = 16;
	generate_keys(client);
	generate_keys(server);
}

int init_message_hash(br_hash_compat_context *h, uint16_t cipher) {
	switch (cipher) {
	case TLS_AES_128_GCM_SHA256:
		br_sha256_init(&h->sha256);
		return 0;
	default:
		return -1;
	}
}

static uint8_t digest_size(const br_hash_class *digest) {
	return (uint8_t)(digest->desc >> BR_HASHDESC_OUT_OFF) & BR_HASHDESC_OUT_MASK;
}

static uint8_t key_length(uint16_t cipher) {
	switch (cipher) {
	case TLS_AES_128_GCM_SHA256:
		return 16;
	default:
		return 0;
	}
}

int generate_handshake_secrets(br_hash_compat_context *msgs, qslice_t client_hello, qslice_t server_hello, br_ec_public_key *pk, br_ec_private_key *sk, uint16_t cipher, qkeyset_t *client, qkeyset_t *server, uint8_t *master_secret) {
	const br_ec_impl *ec = br_ec_get_default();
	if (!ec->mul(pk->q, pk->qlen, sk->x, sk->xlen, pk->curve)) {
		return -1;
	}
	size_t xlen, xoff = ec->xoff(pk->curve, &xlen);
	if (xoff + xlen > pk->qlen) {
		return -1;
	}

	switch (cipher) {
	case TLS_AES_128_GCM_SHA256:
		br_sha256_init(&msgs->sha256);
		break;
	default:
		return -1;
	}

	const br_hash_class *digest = msgs->vtable;
	uint8_t hash_len = digest_size(digest);
	uint8_t key_len = key_length(cipher);

	client->hash_len = server->hash_len = hash_len;
	client->key_len = server->key_len = key_len;
	client->digest = server->digest = digest;

	uint8_t early_secret[QUIC_MAX_SECRET_SIZE];
	uint8_t early_derived[QUIC_MAX_SECRET_SIZE];
	hkdf_extract(digest, NULL, 0, NULL, 0, early_secret);
	hkdf_expand_label(digest, hash_len, early_secret, "quic derived", NULL, 0, early_derived, hash_len);

	uint8_t msg_hash[QUIC_MAX_HASH_SIZE];
	msgs->vtable->update(&msgs->vtable, client_hello.p, client_hello.e - client_hello.p);
	msgs->vtable->update(&msgs->vtable, server_hello.p, server_hello.e - server_hello.p);
	msgs->vtable->out(&msgs->vtable, msg_hash);

	uint8_t hs_secret[QUIC_MAX_SECRET_SIZE];
	hkdf_extract(digest, early_derived, hash_len, pk->q + xoff, xlen, hs_secret);
	hkdf_expand_label(digest, hash_len, hs_secret, "quic c hs traffic", msg_hash, hash_len, client->secret, hash_len);
	hkdf_expand_label(digest, hash_len, hs_secret, "quic s hs traffic", msg_hash, hash_len, server->secret, hash_len);

	uint8_t derived[QUIC_MAX_SECRET_SIZE];
	hkdf_expand_label(digest, hash_len, hs_secret, "quic derived", NULL, 0, derived, hash_len);
	hkdf_extract(digest, derived, hash_len, NULL, 0, master_secret);

	generate_keys(client);
	generate_keys(server);
	return 0;
}

void generate_protected_secrets(const br_hash_class *const *msgs, const uint8_t *master_secret, uint16_t cipher, qkeyset_t *client, qkeyset_t *server) {
	const br_hash_class *digest = *msgs;
	uint8_t hash_len = digest_size(digest);
	client->key_len = server->key_len = key_length(cipher);
	client->hash_len = server->hash_len = hash_len;

	uint8_t msg_hash[QUIC_MAX_HASH_SIZE];
	(*msgs)->out(msgs, msg_hash);

	hkdf_expand_label(digest, hash_len, master_secret, "quic c ap traffic", msg_hash, hash_len, client->secret, hash_len);
	hkdf_expand_label(digest, hash_len, master_secret, "quic s ap traffic", msg_hash, hash_len, server->secret, hash_len);

	generate_keys(client);
	generate_keys(server);
}

#define PKT_NUM_KEYSZ 16

// used for both encryption and decryption
static void protect_packet_number(qkeyset_t *k, uint8_t *pktnum, const uint8_t *payload, const uint8_t *end) {
	const uint8_t *sample = pktnum + 4;
	if (sample + PKT_NUM_KEYSZ > end) {
		sample = end - PKT_NUM_KEYSZ;
	}
	// bearssl takes the AES CTR IV as 12B IV | 4B counter
	// QUIC wants to provide a 16B IV so we need to break them apart again from the sample
	k->pn.vtable->run(&k->pn.vtable, sample, big_32(sample + PKT_NUM_KEYSZ - 4), pktnum, payload - pktnum);
}

void encrypt_packet(qkeyset_t *k, uint64_t pktnum, uint8_t *pkt_begin, uint8_t *packet_number, uint8_t *enc_begin, uint8_t *pkt_end) {
	uint8_t *tag = pkt_end - QUIC_TAG_SIZE;
	reset_keyset(k, pktnum);
	br_gcm_aad_inject(&k->gcm, pkt_begin, enc_begin - pkt_begin);
	br_gcm_flip(&k->gcm);
	br_gcm_run(&k->gcm, 1, enc_begin, tag - enc_begin);
	br_gcm_get_tag(&k->gcm, tag);
	protect_packet_number(k, packet_number, enc_begin, pkt_end);
}

int64_t decrypt_packet(qkeyset_t *k, uint8_t *pkt_begin, uint8_t *packet_number, uint8_t *pkt_end, qslice_t *pkt_data) {
	if (!k->digest) {
		// key not initialized yet
		return -1;
	}
	// copy out the encrypted packet number
	// this way we can assume a 4B packet number
    // and copy the payload bytes 
	if (packet_number + 1 + QUIC_TAG_SIZE > pkt_end) {
		return -1;
	}
	qslice_t s = { packet_number, packet_number + 4 };
	uint8_t tmp[4];
	memcpy(tmp, s.p, 4);
	protect_packet_number(k, s.p, s.e, pkt_end);
	int64_t pktnum = decode_packet_number(&s);
	if (pktnum < 0) {
		return -1;
	}
	memcpy(s.p, tmp + (s.p - packet_number), 4 - (s.p - packet_number));

	uint8_t *enc_begin = s.p;
	uint8_t *tag = pkt_end - QUIC_TAG_SIZE;
	if (tag < enc_begin) {
		return -1;
	}
	reset_keyset(k, (uint64_t)pktnum);
	br_gcm_aad_inject(&k->gcm, pkt_begin, enc_begin - pkt_begin);
	br_gcm_flip(&k->gcm);
	br_gcm_run(&k->gcm, 0, enc_begin, tag - enc_begin);
	if (!br_gcm_check_tag(&k->gcm, tag)) {
		return -1;
	}

	pkt_data->p = enc_begin;
	pkt_data->e = tag;
	return pktnum;
}

static const char server_context[] = "TLS 1.3, server CertificateVerify";
static const char client_context[] = "TLS 1.3, client CertificateVerify";

size_t generate_cert_verify(bool is_client, const br_hash_class *const *msgs, uint8_t *out) {
	assert(64 + sizeof(server_context) + digest_size(*msgs) <= QUIC_MAX_CERT_VERIFY_SIZE);
	uint8_t *start = out;
	memset(out, 0x20, 64);
	out += 64;
	if (is_client) {
		out = append(out, client_context, sizeof(client_context));
	} else {
		out = append(out, server_context, sizeof(server_context));
	}
	(*msgs)->out(msgs, out);
	out += digest_size(*msgs);
	return out - start;
}

size_t generate_finish_verify(qkeyset_t *k, const br_hash_class *const *msgs, uint8_t *out) {
	uint8_t finished_key[QUIC_MAX_HASH_SIZE];
	hkdf_expand_label(k->digest, k->hash_len, k->secret, "quic finished", NULL, 0, finished_key, k->hash_len);
	uint8_t msghash[QUIC_MAX_HASH_SIZE];
	(*msgs)->out(msgs, msghash);
	br_hmac_key_context kc;
	br_hmac_context ctx;
	br_hmac_key_init(&kc, k->digest, finished_key, k->hash_len);
	br_hmac_init(&ctx, &kc, 0);
	br_hmac_update(&ctx, msghash, k->hash_len);
	br_hmac_out(&ctx, out);
	return k->hash_len;
}

int verify_rsa_pkcs1(const br_hash_class *digest, const uint8_t *hash_oid, br_x509_pkey *pk, qslice_t sig, const uint8_t *verify, size_t vlen) {
	if (pk->key_type != BR_KEYTYPE_RSA) {
		return -1;
	}

	br_rsa_pkcs1_vrfy fn = br_rsa_i62_pkcs1_vrfy_get();
	if (!fn) {
		fn = &br_rsa_i31_pkcs1_vrfy;
	}

	uint8_t hash1[QUIC_MAX_HASH_SIZE], hash2[QUIC_MAX_HASH_SIZE];
	if (!fn(sig.p, sig.e - sig.p, hash_oid, digest_size(digest), &pk->key.rsa, hash1)) {
		return -1;
	}
	br_hash_compat_context h;
	digest->init(&h.vtable);
	digest->update(&h.vtable, verify, vlen);
	digest->out(&h.vtable, hash2);
	return memcmp(hash1, hash2, digest_size(digest));
}



