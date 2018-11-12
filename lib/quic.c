#include "quic.h"
#include <cutils/endian.h>
#include <cutils/char-array.h>
#include <assert.h>

#define QUIC_VERSION UINT32_C(0xFF00000F)
#define DEFAULT_SERVER_ID_LEN 8

// packet types
#define LONG_HEADER_FLAG 0x80
#define INITIAL 0xFF

// frame types
#define PADDING 0
#define RST_STREAM 1
#define CONNECTION_CLOSE 2
#define APPLICATION_CLOSE 3
#define MAX_DATA 4
#define MAX_STREAM_DATA 5
#define MAX_STREAM_ID 6
#define PING 7
#define BLOCKED 8
#define STREAM_BLOCKED 9
#define STREAM_ID_BLOCKED 0x0A
#define NEW_CONNECTION_ID 0x0B
#define STOP_SENDING 0x0C
#define RETIRE_CONNECTION_ID 0x0D
#define PATH_CHALLENGE 0x0E
#define PATH_RESPONSE 0x0F
#define STREAM 0x10
#define STREAM_OFF_FLAG 4
#define STREAM_LEN_FLAG 2
#define STREAM_FIN_FLAG 1
#define STREAM_MASK 0xF8
#define CRYPTO 0x18
#define NEW_TOKEN 0x19
#define ACK 0x1A
#define ACK_MASK 0xFE
#define ACK_ECN_FLAG 1

// TLS records
#define TLS_RECORD_HEADER_SIZE 4
#define CLIENT_HELLO 1
#define SERVER_HELLO 2
#define NEW_SESSION_TICKET 4
#define END_OF_EARLY_DATA 5
#define ENCRYPTED_EXTENSIONS 6
#define CERTIFICATE 11
#define CERTIFICATE_REQUEST 13
#define CERTIFICATE_VERIFY 15
#define FINISHED 20
#define KEY_UPDATE 24
#define MESSAGE_HASH 254

#define TLS_LEGACY_VERSION 0x303
#define TLS_VERSION 0x304
#define TLS_HELLO_RANDOM_SIZE 20

// TLS ciphers
#define TLS_AES_128_GCM_SHA256 0x1301

#define EC_KEY_UNCOMPRESSED 4

// TLS compression methods
#define TLS_COMPRESSION_NULL 0

// TLS signature algorithms
#define RSA_PKCS1_SHA256 0x0401
#define RSA_PKCS1_SHA384 0x0501
#define RSA_PKCS1_SHA512 0x0601
#define ECDSA_SECP256R1_SHA256 0x0403
#define ECDSA_SECP384R1_SHA384 0x0503
#define ECDSA_SECP512R1_SHA512 0x0603
#define ED25519 0x0807
#define ED448 0x0808
#define RSA_PSS_SHA256 0x0809
#define RSA_PSS_SHA384 0x080A
#define RSA_PSS_SHA512 0x080B

// TLS extensions
#define TLS_EXTENSION_HEADER_SIZE 4
#define SERVER_NAME 0
#define MAX_FRAGMENT_LENGTH 1
#define STATUS_REQUEST 5
#define SUPPORTED_GROUPS 10
#define SIGNATURE_ALGORITHMS 13
#define USE_SRTP 14
#define HEARTBEAT 15
#define APP_PROTOCOL 16
#define SIGNED_CERTIFICATE_TIMESTAMP 18
#define CLIENT_CERTIFICATE_TYPE 19
#define SERVER_CERTIFICATE_TYPE 20
#define TLS_PADDING 21
#define PRE_SHARED_KEY 41
#define EARLY_DATA 42
#define SUPPORTED_VERSIONS 43
#define COOKIE 44
#define PSK_KEY_EXCHANGE_MODES 45
#define CERTIFICATE_AUTHORITIES 47
#define OID_FILTERS 48
#define POST_HANDSHAKE_AUTH 49
#define SIGNATURE_ALGORITHMS_CERT 50
#define KEY_SHARE 51
#define QUIC_TRANSPORT_PARAMETERS 0xFFA5

// server name
#define HOST_NAME_TYPE 0

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

void qc_init(qconnection_t *c) {
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
	id->len = DEFAULT_SERVER_ID_LEN;
	(*prng)->generate(prng, id->id, DEFAULT_SERVER_ID_LEN);
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

static uint8_t encode_id_len(qconnection_id_t *id) {
	return id->len ? (id->len - 3) : 0;
}

static uint8_t decode_id_len(uint8_t val) {
	return val ? (val + 3) : 0;
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

static int64_t decode_varint(uint8_t **p, uint8_t *e) {
	if (*p == e) {
		return -1;
	}
	uint8_t *s = (*p)++;
	uint8_t hdr = *s;
	switch (hdr >> 6) {
	case 0:
		return hdr;
	case 1:
		if (*p == e) {
			return -1;
		}
		*p += 1;
		return big_16(s) & 0x3FFF;
	case 2:
		if (*p + 3 > e) {
			return -1;
		}
		*p += 3;
		return big_32(s) & UINT32_C(0x3FFFFFFF);
	default:
		if (*p + 7 > e) {
			return -1;
		}
		*p += 7;
		return big_64(s) & UINT64_C(0x3FFFFFFFFFFFFFFF);
	}
}

static uint8_t *encode_packet_number_backwards(uint8_t *p, uint64_t val) {
	// for now just use the 4B form
	p -= 4; write_big_32(p, (uint32_t)val | UINT32_C(0xC0000000));
	return p;
}

static int64_t decode_packet_number(uint8_t **p, uint8_t *e, int64_t base) {
	if (*p == e) {
		return -1;
	}
	uint8_t *s = (*p)++;
	uint8_t hdr = *s;
	switch (hdr >> 6) {
	default:
		return (base & UINT64_C(0xFFFFFFFFFFFFFF80)) | (hdr & 0x7F);
	case 2:
		if (*p == e) {
			return -1;
		}
		return (base & UINT64_C(0xFFFFFFFFFFFFC000)) | ((uint16_t)hdr & 0x3F) | *((*p)++);
	case 3:
		if (*p + 3 > e) {
			return -1;
		}
		*p += 3;
		return (base & UINT64_C(0xFFFFFFFFC0000000)) | (big_32(s) & UINT32_C(0x3FFFFFFF));
	}
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
	uint8_t *e = packet + sizeof(packet);
	// start with encoding the data and then add the header in front of it
	// header is variable length due to the length field
	uint8_t *data = p = packet
		+ 1 // packet type
		+ 4 // version
		+ 1 // dcil/scil
		+ 18 // destination id
		+ 18 // source id
		+ 4 // length
		+ 4 // packet number
		+ 1 // crypto frame
		+ 1 // crypto offset
		+ 4; // crypto length

	// client hello record header - will fill out later
	uint8_t *client_hello = p;
	p += TLS_RECORD_HEADER_SIZE;

	// legacy version
	write_big_16(p, TLS_LEGACY_VERSION); p += 2;

	// random field
	c->rand.vtable->generate(&c->rand.vtable, p, TLS_HELLO_RANDOM_SIZE);
	p += TLS_HELLO_RANDOM_SIZE;

	// legacy session ID - not used in QUIC
	*p++ = 0;

	// cipher suites
	write_big_16(p, 2); p += 2;
	write_big_16(p, TLS_AES_128_GCM_SHA256); p += 2;

	// compression methods
	*p++ = 1;
	*p++ = TLS_COMPRESSION_NULL;

	// extensions size in bytes - will fill out later
	uint8_t *extensions = p; p += 2;

	// server name
	uint8_t *sni = p;
	p += 2 + 2 + 2 + 1 + 2 + c->server_name.len;
	if (p > e) {
		return -1;
	}
	write_big_16(sni, SERVER_NAME);
	write_big_16(sni+2, c->server_name.len + 2 + 1 + 2);
	write_big_16(sni+4, c->server_name.len + 2 + 1);
	sni[5] = HOST_NAME_TYPE;
	write_big_16(sni+7, c->server_name.len);
	memcpy(sni+9, c->server_name.c_str, c->server_name.len);

	// supported groups
	uint8_t *ecc = p;
	size_t num_groups = 1;
	p += 2 + 2 + 2 + (2 * num_groups);
	if (p > e) {
		return -1;
	}
	write_big_16(ecc, SUPPORTED_GROUPS);
	write_big_16(ecc + 2, 2 + (2 * num_groups));
	write_big_16(ecc + 4, 2 * num_groups);
	write_big_16(ecc + 6, BR_EC_curve25519);

	// signature algorithms
	uint8_t *sig = p;
	size_t num_algos = 2;
	p += 2 + 2 + 2 + (2 * num_algos);
	if (p > e) {
		return -1;
	}
	write_big_16(sig, SIGNATURE_ALGORITHMS);
	write_big_16(sig + 2, 2 + (2 * num_algos));
	write_big_16(sig + 4, 2 * num_algos);
	write_big_16(sig + 6, ED25519);
	write_big_16(sig + 8, RSA_PKCS1_SHA256);

	// supported versions
	uint8_t *ver = p;
	size_t num_versions = 2;
	p += 2 + (2 * num_versions);
	if (p > e) {
		return -1;
	}
	write_big_16(ver, SUPPORTED_VERSIONS);
	write_big_16(ver + 2, 2 * num_versions);
	write_big_16(ver + 4, 0x3A3A); // grease
	write_big_16(ver + 6, TLS_VERSION);

	// key share
	const br_ec_impl *ec = br_ec_get_default();
	uint8_t key25519[BR_EC_KBUF_PRIV_MAX_SIZE];
	uint8_t pub25519[BR_EC_KBUF_PUB_MAX_SIZE];
	br_ec_private_key sk_25519;
	br_ec_public_key pk_25519;
	br_ec_keygen(&c->rand.vtable, ec, &sk_25519, key25519, BR_EC_curve25519);
	br_ec_compute_pub(ec, &pk_25519, pub25519, &sk_25519);
	size_t key_share_size = 0;
	key_share_size += 2 + 2 + 1 + pk_25519.qlen;
	uint8_t *ks = p;
	p += TLS_RECORD_HEADER_SIZE + 2 + key_share_size;
	if (p > e) {
		return -1;
	}
	write_big_16(ks, KEY_SHARE);
	write_big_16(ks + 2, key_share_size);
	ks += 4;
	write_big_16(ks, BR_EC_curve25519);
	write_big_16(ks + 2, 1 + pk_25519.qlen);
	ks[2] = EC_KEY_UNCOMPRESSED;
	memcpy(ks + 3, pk_25519.q, pk_25519.qlen);

	client_hello[0] = CLIENT_HELLO;
	write_big_24(client_hello + 1, p - client_hello - TLS_RECORD_HEADER_SIZE);

	// add some padding
	if (p < data + 1200) {
		memset(p, 0, data + 1200 - p);
		p = data + 1200;
	}

	uint8_t *tag = p; p += AEAD_TAG_SIZE; // fill out the tag later
	uint8_t *end = p;

	p = data;
	uint8_t *pktnum = p = encode_packet_number_backwards(p, 0);
	p = encode_varint_backwards(p, end - p); // packet length
	p = encode_varint_backwards(p, 0); // token length
	p -= c->local_id->len; memcpy(p, c->local_id->id, c->local_id->len);
	p -= c->peer_id->len; memcpy(p, c->peer_id->id, c->peer_id->len);
	*(--p) = (encode_id_len(c->peer_id) << 4) | encode_id_len(c->local_id);
	p -= 4; write_big_32(p, QUIC_VERSION);
	*(--p) = PACKET_INITIAL;

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

static int process_frames(qconnection_t *c, uint8_t *p, uint8_t *e) {
	while (p < e) {
		// We only support frame types < 0x40. We should error on any type not supported.
		// The standard requires shortest varint form. Thus we can ignore the varint encoding
		uint8_t frame_type = *(p++);
		if ((frame_type & STREAM_MASK) == STREAM) {

		} else if ((frame_type & ACK_MASK) == ACK) {

		} else {
			switch (frame_type) {
			case PADDING:
				while (p < e && *p) {
					p++;
				}
				break;
			default:
				return -1;
			}
		}
	}
	return 0;
}

int qc_process(qconnection_t *c, void *buf, size_t len, const struct sockaddr *sa, size_t salen, tick_t rxtime) {
	
	uint8_t *p = buf;
	uint8_t *e = p + len;

	while (p < e) {
		if (p[0] & LONG_HEADER_FLAG) {
			if (e - p < 6) {
				return -1;
			}
			uint32_t version = big_32(p + 1);
			if (version != QUIC_VERSION) {
				// TODO send version negotiation
				return -1;
			}
			uint8_t dcil = decode_id_len(p[5] >> 4);
			uint8_t scil = decode_id_len(p[5] & 0xF);
			if (dcil != DEFAULT_SERVER_ID_LEN) {
				return -1;
			}
			p += 6;

			switch (p[0]) {
			case INITIAL: {
				c->local_id = &c->local_ids[0];
				c->local_id->len = dcil;
				memcpy(c->local_id->id, p, dcil);
				p += dcil;
				c->peer_id = &c->peer_ids[0];
				c->peer_id->len = scil;
				memcpy(c->peer_id->id, p, scil);
				p += scil;

				struct aead_aes_128_gcm client, server;
				generate_initial_secrets(c->local_id, &client, &server);
				init_aead_aes_128_gcm(&client);

				int64_t toksz = decode_varint(&p, e);
				if (toksz < 0 || toksz >(int64_t)(e - p)) {
					return -1;
				}
				p += (size_t)toksz; // skip over token

				int64_t paysz = decode_varint(&p, e);
				if (paysz < 0 || paysz >(int64_t)(e - p)) {
					return -1;
				}

				// copy out the encrypted packet number
				// this way we can assume a 4B packet number
				// and copy the payload bytes 
				uint8_t *pkte = p + paysz;
				uint8_t tmp[4];
				memcpy(tmp, p, 4);
				protect_packet_number(&client, p, p + 4, pkte);
				uint8_t *payload = p;
				int64_t pktnum = decode_packet_number(&p, pkte, 0); // TODO: offset from last packet num
				if (pktnum < 0) {
					return -1;
				}
				memcpy(p, tmp + (p - payload), 4 - (p - payload));

				if (pkte - p < AEAD_TAG_SIZE) {
					return -1;
				}
				reset_aead_aes_128_gcm(&client, (uint64_t)pktnum);
				br_gcm_aad_inject(&client.gcm, buf, p - (uint8_t*)buf);
				br_gcm_flip(&client.gcm);
				br_gcm_run(&client.gcm, 0, p, pkte - p - AEAD_TAG_SIZE);
				if (!br_gcm_check_tag(&client.gcm, pkte - AEAD_TAG_SIZE)) {
					return -1;
				}

				if (process_frames(c, p, pkte - AEAD_TAG_SIZE)) {
					return -1;
				}

				p = pkte;
				continue;
			}
			}
		} else {
			// short header
			if (e - p < 1 + DEFAULT_SERVER_ID_LEN) {
				return -1;
			}
		}
		switch (c->state) {
		case QC_WAIT_FOR_INITIAL: {
		}
		default:
			return -1;
		}
	}

	return 0;
}
