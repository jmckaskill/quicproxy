#include "quic.h"
#include <cutils/endian.h>
#include <cutils/char-array.h>
#include <assert.h>

#define QUIC_INITIAL 0xFF
#define QUIC_VERSION UINT32_C(0xFF00000F)

static const char prng_nonce[] = "quic-proxy prng nonce";
static const uint8_t initial_salt[] = {
	0x9c, 0x10, 0x8f, 0x98, 0x52, 0x0a, 0x5c, 0x5c,
	0x32, 0x96, 0x8e, 0x95, 0x0e, 0x8a, 0x2c, 0x5f,
	0xe0, 0x6d, 0x6c, 0x38,
};

static inline size_t digest_size(const br_hash_class *digest_class) {
	return (size_t)(digest_class->desc >> BR_HASHDESC_OUT_OFF)
		& BR_HASHDESC_OUT_MASK;
}

void qc_init_client(qconnection_t *c) {
	memset(c, 0, sizeof(*c));
	br_hmac_drbg_init(&c->rand, &br_sha256_vtable, prng_nonce, sizeof(prng_nonce));
}

void qc_add_peer_address(qconnection_t *c, const struct sockaddr *sa, size_t sasz) {
	for (int i = 0; i < QUIC_MAX_ADDR; i++) {
		if (!c->peer_addrs[i].len) {
			memcpy(&c->peer_addrs[i].ss, sa, sasz);
			c->peer_addrs[i].len = sasz;
			break;
		}
	}
}

int qc_lookup_peer_name(qconnection_t *c, const char *server_name, const char *svc_name) {
	if (ca_set(&c->server_name, server_name)) {
		return -1;
	}

	struct addrinfo hints, *result;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	if (getaddrinfo(server_name, svc_name, &hints, &result)) {
		return -1;
	}

	for (struct addrinfo *rp = result; rp != NULL; rp = rp->ai_next) {
		qc_add_peer_address(c, rp->ai_addr, rp->ai_addrlen);
	}

	freeaddrinfo(result);
	return 0;
}

int qc_seed_prng(qconnection_t *c, br_prng_seeder seedfn) {
	return seedfn(&c->rand.vtable) == 0;
}

static void generate_id(const br_prng_class **prng, qconnection_id_t *id) {
	id->len = 8;
	(*prng)->generate(prng, id->id, 8);
}

void qc_generate_ids(qconnection_t *c) {
#if 1
	for (int i = 0; i < QUIC_MAX_IDS; i++) {
		if (!c->local_ids[i].len) {
			generate_id(&c->rand.vtable, &c->local_ids[i]);
		}
	}
	if (!c->local_id) {
		c->local_id = &c->local_ids[0];
	}
	if (!c->peer_id) {
		generate_id(&c->rand.vtable, &c->peer_ids[0]);
		c->peer_id = &c->peer_ids[0];
	}
#else
	memcpy(c->peer_ids[0].id, "\x48\xb7\xfb\x64\x1b\x4f\xac\x70\x94\xd2\xa3\x2b\xa6\xe0\x2a\x8d\x08\xb9", 18);
	c->peer_ids[0].len = 18;
	c->peer_id = &c->peer_ids[0];
	memcpy(c->local_ids[0].id, "\x65\x54\x4c\x46\x31\x80\x03\xcb\xa4\xf2\x6d\x49\x05\xfe\x0f\x7d\xf8", 17);
	c->local_ids[0].len = 17;
	c->local_id = &c->local_ids[0];
#endif
}

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
	uint8_t hk_label[2 + 1 + 16 + 1 + 256], *p = hk_label;
	size_t labelsz = strlen(label);
	assert(labelsz <= 16);
	assert(ctxsz < 256);
	assert(outsz <= UINT16_MAX);
	write_big_16(p, (uint16_t)outsz); p += 2;
	*(p++) = (uint8_t)labelsz;
	memcpy(p, label, labelsz); p += labelsz;
	*(p++) = (uint8_t)ctxsz;
	memcpy(p, context, ctxsz); p += ctxsz;
	hkdf_expand(digest, secret, hk_label, p - hk_label, out, outsz);
}

static void derive_keys(const br_hash_class *digest, const void *secret, void *datakey, void *pnkey, size_t keysz, void *iv, size_t ivsz) {
	hkdf_expand_label(digest, secret, "quic key", NULL, 0, datakey, keysz);
	hkdf_expand_label(digest, secret, "quic pn", NULL, 0, pnkey, keysz);
	hkdf_expand_label(digest, secret, "quic iv", NULL, 0, iv, ivsz);
}

#define AEAD_AES_128_GCM_KEY_SIZE 16
#define AEAD_AES_128_GCM_IV_SIZE 12
#define AEAD_TAG_SIZE 16

struct aead_aes_128_gcm {
	br_aes_gen_ctr_keys data;
	br_aes_gen_ctr_keys pn;
	br_gcm_context gcm;
	uint8_t secret[br_sha256_SIZE];
	uint8_t data_key[AEAD_AES_128_GCM_KEY_SIZE], pn_key[AEAD_AES_128_GCM_KEY_SIZE];
	uint8_t iv[AEAD_AES_128_GCM_IV_SIZE];
};


static void init_aes_ctr(br_aes_gen_ctr_keys *a, const void *key, size_t keysz) {
	if (br_aes_x86ni_ctr_get_vtable()) {
		br_aes_x86ni_ctr_init(&a->c_x86ni, key, keysz);
	} else {
		br_aes_big_ctr_init(&a->c_big, key, keysz);
	}
}

static void init_aead_aes_128_gcm(struct aead_aes_128_gcm *a) {
	br_ghash gh = br_ghash_pclmul_get();
	if (!gh) {
		gh = &br_ghash_ctmul;
	}
	init_aes_ctr(&a->pn, a->pn_key, sizeof(a->pn_key));
	init_aes_ctr(&a->data, a->data_key, sizeof(a->data_key));
	br_gcm_init(&a->gcm, &a->data.vtable, gh);
}

static void reset_aead_aes_128_gcm(struct aead_aes_128_gcm *a, uint64_t pktnum) {
	uint8_t nonce[AEAD_AES_128_GCM_IV_SIZE] = { 0 };
	write_big_64(nonce + sizeof(nonce) - 8, pktnum);
	for (int i = 0; i < sizeof(nonce); i++) {
		nonce[i] ^= a->iv[i];
	}
	br_gcm_reset(&a->gcm, nonce, sizeof(nonce));
}
 
static void generate_initial_secrets(const qconnection_id_t *id, struct aead_aes_128_gcm *client, struct aead_aes_128_gcm *server) {
	uint8_t initial_secret[br_sha256_SIZE];
	hkdf_extract(&br_sha256_vtable, initial_salt, sizeof(initial_salt), id->id, id->len, initial_secret);
	hkdf_expand_label(&br_sha256_vtable, initial_secret, "quic client in", NULL, 0, client->secret, br_sha256_SIZE);
	hkdf_expand_label(&br_sha256_vtable, initial_secret, "quic server in", NULL, 0, server->secret, br_sha256_SIZE);
	derive_keys(&br_sha256_vtable, client->secret, client->data_key, client->pn_key, sizeof(client->data_key), client->iv, sizeof(client->iv));
	derive_keys(&br_sha256_vtable, server->secret, server->data_key, server->pn_key, sizeof(server->data_key), server->iv, sizeof(server->iv));
}

static uint8_t encoded_id_len(qconnection_id_t *id) {
	return id->len ? (id->len - 3) : 0;
}

static uint8_t *encode_varint_backwards(uint8_t *p, uint64_t val) {
	if (val < 0x40) {
		*(--p) = (uint8_t)val;
	} else if (val < 0x4000) {
		p -= 2;	write_big_16(p, (uint16_t)val | 0x4000);
	} else if (val < 0x40000000) {
		p -= 4; write_big_32(p, (uint32_t)val | UINT32_C(0x80000000));
	} else {
		p -= 8; write_big_64(p, val | UINT64_C(0xC000000000000000));
	}
	return p;
}

static uint8_t *encode_packet_number_backwards(uint8_t *p, uint64_t val) {
	// for now just use the 4B form
	p -= 4; write_big_32(p, (uint32_t)val | UINT32_C(0xC0000000));
	return p;
}

#define PKT_NUM_KEYSZ 16

static void protect_packet_number(struct aead_aes_128_gcm *a, uint8_t *pktnum, const uint8_t *payload, const uint8_t *end) {
	const uint8_t *sample = pktnum + 4;
	if (sample + PKT_NUM_KEYSZ > end) {
		sample = end - PKT_NUM_KEYSZ;
	}
	// bearssl takes the AES CTR IV as 12B IV | 4B counter
	// QUIC wants to provide a 16B IV so we need to break them apart again from the sample
	a->pn.vtable->run(&a->pn.vtable, sample, big_32(sample + PKT_NUM_KEYSZ - 4), pktnum, payload - pktnum);
}

int qc_send_client_hello(qconnection_t *c) {
	struct aead_aes_128_gcm client, server;
	generate_initial_secrets(c->peer_id, &client, &server);
	init_aead_aes_128_gcm(&client);

	uint8_t packet[1600];
	// start with encoding the data and then add the header in front of it
	// header is variable length due to the length field
	uint8_t *payload = packet + 1 + 4 + 1 + 18 + 18 + 8 + 4;
	uint8_t *p = payload;
	memset(p, 0, 1200); p += 1200;
	uint8_t *tag = p; p += AEAD_TAG_SIZE; // fill out the tag later
	uint8_t *end = p;

	p = payload;
	uint8_t *pktnum = p = encode_packet_number_backwards(p, 0);
	p = encode_varint_backwards(p, end - p); // packet length
	p = encode_varint_backwards(p, 0); // token length
	p -= c->local_id->len; memcpy(p, c->local_id->id, c->local_id->len);
	p -= c->peer_id->len; memcpy(p, c->peer_id->id, c->peer_id->len);
	*(--p) = (encoded_id_len(c->peer_id) << 4) | encoded_id_len(c->local_id);
	p -= 4; write_big_32(p, QUIC_VERSION);
	*(--p) = QUIC_INITIAL;

	reset_aead_aes_128_gcm(&client, 0);
	br_gcm_aad_inject(&client.gcm, p, payload - p);
	br_gcm_flip(&client.gcm);
	br_gcm_run(&client.gcm, 1, payload, tag - payload);
	br_gcm_get_tag(&client.gcm, tag);
	protect_packet_number(&client, pktnum, payload, end);

	bool did_send = false;
	tick_t sent = 0;

	for (int i = 0; i < QUIC_MAX_ADDR; i++) {
		qconnection_addr_t *a = &c->peer_addrs[i];
		if (a->len && !c->send(c->user, p, end - p, (struct sockaddr*)&a->ss, a->len, &sent)) {
			did_send = true;
		}
	}

	return did_send ? 0 : -1;
}

