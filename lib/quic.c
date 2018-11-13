#include "quic.h"
#include "packets.h"
#include <cutils/endian.h>
#include <cutils/char-array.h>
#include <assert.h>


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
	slice_string(&c->ciphers, "\x13\x01");
	slice_string(&c->groups, "\x00\x1D");
	slice_string(&c->algorithms, "\x04\x01");
	c->peer_addr = &c->peer_addrs[0];
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

int qc_start_connect(qconnection_t *c) {
	struct aead_aes_128_gcm client, server;
	generate_initial_secrets(c->peer_id, &client, &server);
	init_aead_aes_128_gcm(&client);

	uint8_t random[TLS_HELLO_RANDOM_SIZE];
	c->rand.vtable->generate(&c->rand.vtable, random, sizeof(random));

	struct client_hello ch;
	slice_all(&ch.server_name, c->server_name);
	ch.ciphers = c->ciphers;
	ch.groups = c->groups;
	ch.algorithms = c->algorithms;
	ch.random = random;

	// generate a public/private key for each offerred cipher
	const br_ec_impl *ec = br_ec_get_default();
	br_ec_private_key pk[TLS_MAX_KEY_SHARE];
	uint8_t keys[TLS_MAX_KEY_SHARE * (BR_EC_KBUF_PRIV_MAX_SIZE + BR_EC_KBUF_PUB_MAX_SIZE)];
	uint8_t *k = keys;
	ch.key_num = ch.ciphers.len / 2;
	for (size_t i = 0; i < ch.key_num; i++) {
		k += br_ec_keygen(&c->rand.vtable, ec, &pk[i], k, big_16(&ch.groups.c_str[i*2]));
		k += br_ec_compute_pub(ec, &ch.keys[i], k, &pk[i]);
	}

	// start with encoding the data and then add the header in front of it
	// header is variable length due to the length field
	uint8_t packet[1600];
	uint8_t *p = packet
		+ 1 // packet type
		+ 4 // version
		+ 1 // dcil/scil
		+ 18 // destination id
		+ 18 // source id
		+ 4 // token length
		+ 0 // token
		+ 4 // length
		+ 4 // packet number
		+ 1 // crypto frame
		+ 8 // crypto offset
		+ 4 // crypto length
		+ 4; // TLS ClientHello record header

	uint8_t *hello = p;
	if (encode_client_hello(&p, packet + sizeof(packet), &ch)) {
		return -1;
	}
	uint8_t *hello_end = p;
	
	// add some padding
	if (p < packet + 1200) {
		memset(p, 0, packet + 1200 - p);
		p = packet + 1200;
	}

	uint8_t *tag = p;
	uint8_t *end = p + AEAD_TAG_SIZE; // fill out the tag later

	p = hello;
	write_big_24(p - 3, (uint32_t)(hello_end - p)); p -= 3;
	*(--p) = CLIENT_HELLO;
	size_t crypto_size = hello_end - p;
	p = encode_varint_backwards(p, crypto_size);
	p = encode_varint_backwards(p, c->tx_next_packet);
	*(--p) = CRYPTO;
	uint8_t *payload = p;
	p = encode_packet_number_backwards(p, c->tx_next_packet);
	uint8_t *pktnum = p;
	p = encode_varint_backwards(p, end - p); // packet length
	p = encode_varint_backwards(p, 0); // token length
	p -= c->local_id->len; memcpy(p, c->local_id->id, c->local_id->len);
	p -= c->peer_id->len; memcpy(p, c->peer_id->id, c->peer_id->len);
	*(--p) = (encode_id_len(c->peer_id->len) << 4) | encode_id_len(c->local_id->len);
	p -= 4; write_big_32(p, QUIC_VERSION);
	*(--p) = INITIAL;

	reset_aead_aes_128_gcm(&client, c->tx_next_packet);
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

	if (!did_send) {
		return -1;
	}

	c->tx_next_packet++;
	c->tx_crypto_offset += crypto_size;
	return 0;
}

static int send_server_hello(qconnection_t *c, const struct client_hello *ch) {
	struct aead_aes_128_gcm client, server;
	generate_initial_secrets(c->local_id, &client, &server);
	init_aead_aes_128_gcm(&server);

	uint8_t random[TLS_HELLO_RANDOM_SIZE];
	c->rand.vtable->generate(&c->rand.vtable, random, sizeof(random));

	struct server_hello sh;
	sh.random = random;
	sh.cipher = TLS_AES_128_GCM_SHA256;

	// generate the server key
	const br_ec_impl *ec = br_ec_get_default();
	br_ec_private_key pk;
	uint8_t key[BR_EC_KBUF_PRIV_MAX_SIZE + BR_EC_KBUF_PUB_MAX_SIZE], *k = key;
	k += br_ec_keygen(&c->rand.vtable, ec, &pk, k, BR_EC_curve25519);
	k += br_ec_compute_pub(ec, &sh.key, k, &pk);

	uint8_t packet[1500];
	uint8_t *p = packet;

	// header
	*(p++) = INITIAL;
	p = write_big_32(p, QUIC_VERSION);

	// connection IDs
	*(p++) = (encode_id_len(c->peer_id->len) << 4) | encode_id_len(c->local_id->len);
	memcpy(p, c->peer_id, c->peer_id->len); p += c->peer_id->len;
	memcpy(p, c->local_id, c->local_id->len); p += c->local_id->len;

	// token
	*(p++) = 0;

	// length
	uint8_t *packet_length = p;
	p += 2; // fill out later

	// packet number
	uint8_t *pktnum = p;
	p = encode_packet_number(p, c->tx_next_packet, 0); // TODO: use correct base

	// CRYPTO frame
	uint8_t *payload = p;
	*(p++) = CRYPTO;
	p = encode_varint(p, c->tx_crypto_offset);
	uint8_t *crypto_length = p;
	p += 2; // fill out later

	// TLS record header
	*(p++) = SERVER_HELLO;
	uint8_t *tls_length = p;
	p += 3; // fill out later

	if (encode_server_hello(&p, packet + sizeof(packet), &sh)) {
		return -1;
	}

	// tag
	uint8_t *tag = p;
	p += AEAD_TAG_SIZE;

	// fill out sizes
	write_big_24(tls_length, (uint32_t)(tag - tls_length - 3));
	write_big_16(crypto_length, VARINT_16 | (uint16_t)(tag - crypto_length - 2));
	write_big_16(packet_length, VARINT_16 | (uint16_t)(p - packet_length - 2));

	// encrypt
	reset_aead_aes_128_gcm(&server, c->tx_next_packet);
	br_gcm_aad_inject(&server.gcm, packet, payload - packet);
	br_gcm_flip(&server.gcm);
	br_gcm_run(&server.gcm, 1, payload, tag - payload);
	br_gcm_get_tag(&server.gcm, tag);
	protect_packet_number(&server, pktnum, payload, p);

	// send
	tick_t sent;
	if (c->send(c->user, packet, p - packet, (struct sockaddr*)&c->peer_addr->ss, c->peer_addr->len, &sent)) {
		return -1;
	}

	c->tx_next_packet++;
	c->tx_crypto_offset += tag - crypto_length - 2;
	return 0;
}

static int update_crypto_buffer(struct qcrypto_buffer *b, enum qcrypto_level level, uint64_t off, uint8_t *p, size_t len) {
	if (level > b->level && !off) {
		// we've increased our crypto level
		b->level = level;
		b->off = 0;
		b->used = b->have = 0;
	} else if (level != b->level || off != b->off) {
		// out of order packet, don't ack the packet
		// so we get it later once it's in order
		return -1;
	}

	size_t have = b->have - b->used;
	if (have + len > sizeof(b->buffer)) {
		// too much data
		return -1;
	} else if (have) {
		// compact the remaining buffer from last time
		// and add the new data
		memmove(b->buffer, b->buffer + b->used, have);
		memcpy(b->buffer + have, p, len);
		b->used = 0;
		b->have = have + len;
		b->ptr = NULL;
		b->end = NULL;
	} else {
		b->ptr = p;
		b->end = p + len;
	}

	b->off = off + len;
	return 0;
}

static uint8_t *peek_crypto_buffer(struct qcrypto_buffer *b, size_t need) {
	if (b->ptr + need <= b->end) {
		// can service from the saved pointer
		return b->ptr;
	} else if (b->used + need <= b->have) {
		// can service from the buffer
		return b->buffer + b->used;
	} else {
		if (b->ptr < b->end) {
			// store the data away for next time
			b->used = 0;
			b->have = b->end - b->ptr;
			memcpy(b->buffer, b->ptr, b->have);
		}
		b->ptr = b->end = NULL;
		return NULL;
	}
}

static void consume_crypto_buffer(struct qcrypto_buffer *b, size_t consume) {
	if (b->ptr) {
		b->ptr += consume;
	} else {
		b->used += consume;
	}
}

static int process_frames(qconnection_t *c, uint8_t *p, uint8_t *e, enum qcrypto_level level) {
	while (p < e) {
		// We only support frame types < 0x40. We should error on any type not supported.
		// The standard requires shortest varint form. Thus we can ignore the varint encoding
		uint8_t frame_type = *(p++);
		if ((frame_type & STREAM_MASK) == STREAM) {

		} else if ((frame_type & ACK_MASK) == ACK) {

		} else if (frame_type == PADDING) {
			do {
				p++;
			} while (p < e && !*p);

		} else if (frame_type == CRYPTO) {
			int64_t off = decode_varint(&p, e);
			int64_t len = decode_varint(&p, e);
			if (off < 0 || len < 0 || (e-p) < len || update_crypto_buffer(&c->rx_crypto, level, (uint64_t)off, p, (size_t)len)) {
				return -1;
			}
			for (;;) {
				uint8_t *hdr = peek_crypto_buffer(&c->rx_crypto, 4);
				if (!hdr) {
					break;
				}
				uint8_t tls_type = hdr[0];
				uint32_t tls_len = big_24(hdr+1);
				hdr = peek_crypto_buffer(&c->rx_crypto, 4 + tls_len);
				if (!hdr) {
					break;
				}
				consume_crypto_buffer(&c->rx_crypto, 4 + tls_len);

				switch (tls_type) {
				case CLIENT_HELLO: {
					struct client_hello ch;
					if (!decode_client_hello(hdr + 4, hdr + 4 + tls_len, &ch)) {
						send_server_hello(c, &ch);
					} else {
						LOG(c->debug, "client hello parse failure");
					}
					break;
				}
				}
			}
		} else {
			return -1;
		}
	}

	return 0;
}

int qc_process(qconnection_t *c, void *buf, size_t len, const struct sockaddr *sa, size_t salen, tick_t rxtime) {
	
	uint8_t *p = buf;
	uint8_t *e = p + len;

	while (p < e) {
		uint8_t hdr = *(p++);
		if (hdr & LONG_HEADER_FLAG) {
			if (e - p < 5) {
				return -1;
			}
			uint32_t version = big_32(p); p += 4;
			if (version != QUIC_VERSION) {
				// TODO send version negotiation
				return -1;
			}
			uint8_t dcil = decode_id_len(*p >> 4);
			uint8_t scil = decode_id_len(*p & 0xF);
			p++;
			if (dcil != DEFAULT_SERVER_ID_LEN) {
				return -1;
			}

			switch (hdr) {
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

				if (process_frames(c, p, pkte - AEAD_TAG_SIZE, QC_INITIAL)) {
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
