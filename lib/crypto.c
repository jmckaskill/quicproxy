#include "crypto.h"
#include "packets.h"
#include <cutils/endian.h>


void hkdf_extract(const br_hash_class *digest, const void *salt, size_t saltsz, const void *ikm, size_t ikmsz, void *out) {
	br_hmac_key_context kc;
	br_hmac_context hmac;
	br_hmac_key_init(&kc, digest, salt, saltsz);
	br_hmac_init(&hmac, &kc, 0);
	br_hmac_update(&hmac, ikm, ikmsz);
	br_hmac_out(&hmac, out);
}

void hkdf_expand(const br_hash_class *digest, const void *secret, const void *info, size_t infosz, void *out, size_t outsz) {
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

void hkdf_expand_label(const br_hash_class *digest, const void *secret, const char *label, const void *context, size_t ctxsz, void *out, size_t outsz) {
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

static void init_aes_ctr(br_aes_gen_ctr_keys *a, const void *key, size_t keysz) {
	if (br_aes_x86ni_ctr_get_vtable()) {
		br_aes_x86ni_ctr_init(&a->c_x86ni, key, keysz);
	} else {
		br_aes_big_ctr_init(&a->c_big, key, keysz);
	}
}

void init_keyset(qkeyset_t *k) {
	hkdf_expand_label(k->digest, k->secret, "quic key", NULL, 0, k->data_key, k->key_len);
	hkdf_expand_label(k->digest, k->secret, "quic pn", NULL, 0, k->pn_key, k->key_len);
	hkdf_expand_label(k->digest, k->secret, "quic iv", NULL, 0, k->data_iv, sizeof(k->data_iv));
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
	uint8_t initial_secret[br_sha256_SIZE];
	hkdf_extract(&br_sha256_vtable, initial_salt, sizeof(initial_salt), id->id, id->len, initial_secret);
	hkdf_expand_label(&br_sha256_vtable, initial_secret, "quic client in", NULL, 0, client->secret, br_sha256_SIZE);
	hkdf_expand_label(&br_sha256_vtable, initial_secret, "quic server in", NULL, 0, server->secret, br_sha256_SIZE);
	server->key_len = client->key_len = 16;
	server->digest = client->digest = &br_sha256_vtable;
	init_keyset(client);
	init_keyset(server);
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

int generate_handshake_secrets(const br_hash_class *const *msgs, br_ec_public_key *pk, br_ec_private_key *sk, uint16_t cipher, qkeyset_t *client, qkeyset_t *server, uint8_t *master_secret) {
	const br_ec_impl *ec = br_ec_get_default();
	if (!ec->mul(pk->q, pk->qlen, sk->x, sk->xlen, pk->curve)) {
		return -1;
	}
	size_t xlen, xoff = ec->xoff(pk->curve, &xlen);
	if (xoff + xlen > pk->qlen) {
		return -1;
	}

	const br_hash_class *digest = *msgs;
	size_t key_len;
	switch (cipher) {
	case TLS_AES_128_GCM_SHA256:
		key_len = 16;
		digest = &br_sha256_vtable;
		break;
	default:
		return -1;
	}
	client->key_len = server->key_len = key_len;
	client->digest = server->digest = digest;

	uint8_t early_secret[QUIC_MAX_SECRET_SIZE], early_derived[QUIC_MAX_SECRET_SIZE];
	hkdf_extract(digest, NULL, 0, NULL, 0, early_secret);
	hkdf_expand_label(digest, early_secret, "quic derived", NULL, 0, early_derived, digest_size(digest));

	uint8_t msg_hash[QUIC_MAX_SECRET_SIZE];
	(*msgs)->out(msgs, msg_hash);

	uint8_t hs_secret[QUIC_MAX_SECRET_SIZE];
	hkdf_extract(digest, early_derived, digest_size(digest), pk->q + xoff, xlen, hs_secret);
	hkdf_expand_label(digest, hs_secret, "quic c hs traffic", msg_hash, digest_size(digest), client->secret, digest_size(digest));
	hkdf_expand_label(digest, hs_secret, "quic s hs traffic", msg_hash, digest_size(digest), server->secret, digest_size(digest));
	hkdf_expand_label(digest, hs_secret, "quic derived", NULL, 0, master_secret, digest_size(digest));

	init_keyset(client);
	init_keyset(server);
	return 0;
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

