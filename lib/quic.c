#include "quic.h"
#include "packets.h"
#include "crypto.h"
#include <cutils/endian.h>
#include <cutils/char-array.h>
#include <assert.h>


static const char prng_nonce[] = "quic-proxy prng nonce";


static const uint8_t def_ciphers[] = { 0x13, 0x01 };
static const uint8_t def_groups[] = { 0x00, 0x1D };
static const uint8_t def_algorithms[] = { 0x04, 0x01 };

int qc_init(qconnection_t *c, br_prng_seeder seedfn, void *pktbuf, size_t bufsz) {
	memset(c, 0, sizeof(*c));
	br_hmac_drbg_init(&c->rand, &br_sha256_vtable, prng_nonce, sizeof(prng_nonce));
	if (!seedfn || !seedfn(&c->rand.vtable)) {
		return -1;
	}
	c->ciphers.p = (uint8_t*)def_ciphers;
	c->ciphers.e = c->ciphers.p + sizeof(def_ciphers);
	c->groups.p = (uint8_t*)def_groups;
	c->groups.e = c->groups.p + sizeof(def_groups);
	c->algorithms.p = (uint8_t*)def_algorithms;
	c->algorithms.e = c->algorithms.p + sizeof(def_algorithms);
	c->peer_addr = &c->peer_addrs[0];

	uint8_t *p = (uint8_t*)(((uintptr_t)pktbuf + 7) &~7U); // align up
	uint8_t *e = (uint8_t*)(((uintptr_t)pktbuf + bufsz) &~7U); // align down
	bufsz = e - p;

	// split the provided buffer into units of 32 packets so that we can split between tx and rx
	size_t pkts32 = (bufsz / (4 + 32 * sizeof(qtx_packet_t)));
	// qtx_packet_t has tighter alignment requirements so start with that
	c->tx.buf = (qtx_packet_t*)p;
	c->tx.bufsz = pkts32 * 32;

	p = (uint8_t*)(c->tx.buf + c->tx.bufsz);
	c->rx.buf = (uint32_t*)p;
	c->rx.bufsz = pkts32 * 32;

	return 0;
}

void qc_on_accept(qconnection_t *c, const struct sockaddr *sa, size_t sasz) {
	for (int i = 0; i < QUIC_MAX_ADDR; i++) {
		if (!c->peer_addrs[i].len) {
			memcpy(&c->peer_addrs[i].ss, sa, sasz);
			c->peer_addrs[i].len = sasz;
			break;
		}
	}
}

static int lookup_peer_name(qconnection_t *c, const char *server_name, const char *svc_name) {
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
		qc_on_accept(c, rp->ai_addr, rp->ai_addrlen);
	}

	freeaddrinfo(result);
	return 0;
}

static void generate_id(const br_prng_class **prng, qconnection_id_t *id) {
	id->len = DEFAULT_SERVER_ID_LEN;
	(*prng)->generate(prng, id->id, DEFAULT_SERVER_ID_LEN);
}

static void generate_ids(qconnection_t *c) {
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
}

int qc_connect(qconnection_t *c, const char *host_name, const char *svc_name) {
	if (lookup_peer_name(c, host_name, svc_name)) {
		return -1;
	}

	qtx_crypto_t *tx = &c->tx_crypto[QC_INITIAL];

	generate_ids(c);
	generate_initial_secrets(c->peer_id, &c->tkey[QC_INITIAL], &c->rkey[QC_INITIAL]);

	uint8_t random[TLS_HELLO_RANDOM_SIZE];
	c->rand.vtable->generate(&c->rand.vtable, random, sizeof(random));

	struct client_hello ch;
	ch.server_name.p = (uint8_t*)c->server_name.c_str;
	ch.server_name.e = ch.server_name.p + c->server_name.len;
	ch.ciphers = c->ciphers;
	ch.groups = c->groups;
	ch.algorithms = c->algorithms;
	ch.random = random;

	// generate a public/private key for the high priority groups
	const br_ec_impl *ec = br_ec_get_default();
	uint8_t pub_keys[QUIC_MAX_KEYSHARE][BR_EC_KBUF_PUB_MAX_SIZE];
	c->key_num = (c->ciphers.e - c->ciphers.p) / 2;
	if (c->key_num > QUIC_MAX_KEYSHARE) {
		c->key_num = QUIC_MAX_KEYSHARE;
	}
	ch.key_num = c->key_num;
	for (size_t i = 0; i < ch.key_num; i++) {
		br_ec_keygen(&c->rand.vtable, ec, &c->priv_key[i], c->priv_key_data[i], big_16(ch.groups.p + (i*2)));
		br_ec_compute_pub(ec, &ch.keys[i], pub_keys[i], &c->priv_key[i]);
	}

	uint8_t packet[1500];
	qslice_t s = { packet, packet + sizeof(packet) };

	// header
	uint8_t *pkt_begin = s.p;
	*(s.p++) = INITIAL_PACKET;
	s.p = write_big_32(s.p, QUIC_VERSION);

	// connection IDs
	*(s.p++) = (encode_id_len(c->peer_id->len) << 4) | encode_id_len(c->local_id->len);
	s.p = append(s.p, c->peer_id, c->peer_id->len);
	s.p = append(s.p, c->local_id, c->local_id->len);

	// token
	*(s.p++) = 0;

	// length
	s.p += 2; // fill out later

	// packet number
	uint8_t *packet_number = s.p;
	s.p = encode_packet_number(s.p, tx->next);
	uint8_t *enc_begin = s.p;

	// CRYPTO frame
	*(s.p++) = CRYPTO;
	s.p = encode_varint(s.p, tx->offset);
	s.p += 2; // fill out later
	uint8_t *crypto_begin = s.p;

	// TLS record header
	*(s.p++) = CLIENT_HELLO;
	s.p += 3; // fill out later
	uint8_t *hello_begin = s.p;

	if (encode_client_hello(&s, &ch)) {
		return -1;
	}

	uint16_t hello_len = (uint16_t)(s.p - hello_begin);
	uint16_t crypto_len = (uint16_t)(s.p - crypto_begin);
	
	// add some padding
	if (s.p < packet + 1200) {
		memset(s.p, 0, packet + 1200 - s.p);
		s.p = packet + 1200;
	}

	// tag
	s.p += QUIC_TAG_SIZE;
	uint8_t *pkt_end = s.p;

	// fill out sizes
	write_big_24(hello_begin - 3, hello_len);
	write_big_16(crypto_begin-2, VARINT_16 | crypto_len);
	write_big_16(packet_number-2, VARINT_16 | (uint16_t)(pkt_end - packet_number));

	// encrypt
	encrypt_packet(&c->tkey[QC_INITIAL], tx->next, pkt_begin, packet_number, enc_begin, pkt_end);

	if (c->tx_crypto_len + crypto_len > sizeof(c->tx_crypto_data)) {
		return -1;
	}

	bool did_send = false;
	tick_t sent = 0;

	for (int i = 0; i < QUIC_MAX_ADDR; i++) {
		qconnection_addr_t *a = &c->peer_addrs[i];
		if (a->len && !c->send(c->user, pkt_begin, pkt_end - pkt_begin, (struct sockaddr*)&a->ss, a->len, &sent)) {
			did_send = true;
		}
	}

	if (!did_send) {
		return -1;
	}

	c->is_client = true;
	memcpy(c->tx_crypto_data + c->tx_crypto_len, crypto_begin, crypto_len);
	c->tx_crypto_len += crypto_len;
	tx->offsets[tx->next] = tx->offset;
	tx->offset += crypto_len;
	tx->next++;
	return 0;
}

static int send_server_hello(qconnection_t *c, const struct client_hello *ch) {
	qtx_crypto_t *tx = &c->tx_crypto[QC_INITIAL];

	uint8_t random[TLS_HELLO_RANDOM_SIZE];
	c->rand.vtable->generate(&c->rand.vtable, random, sizeof(random));

	struct server_hello sh;
	sh.random = random;
	sh.cipher = TLS_AES_128_GCM_SHA256;

	// generate the server key
	const br_ec_impl *ec = br_ec_get_default();
	uint8_t pub_key[BR_EC_KBUF_PUB_MAX_SIZE];
	c->key_num = 1;
	br_ec_keygen(&c->rand.vtable, ec, &c->priv_key[0], c->priv_key_data, BR_EC_curve25519);
	br_ec_compute_pub(ec, &sh.key, pub_key, &c->priv_key[0]);

	uint8_t packet[1500];
	qslice_t s = { packet, packet + sizeof(packet) };

	// header
	uint8_t *pkt_begin = s.p;
	*(s.p++) = INITIAL_PACKET;
	s.p = write_big_32(s.p, QUIC_VERSION);

	// connection IDs
	*(s.p++) = (encode_id_len(c->peer_id->len) << 4) | encode_id_len(c->local_id->len);
	s.p = append(s.p, c->peer_id, c->peer_id->len);
	s.p = append(s.p, c->local_id, c->local_id->len);

	// token
	*(s.p++) = 0;

	// length
	s.p += 2; // fill out later

	// packet number
	uint8_t *packet_number = s.p;
	s.p = encode_packet_number(s.p, tx->next);
	uint8_t *enc_begin = s.p;

	// CRYPTO frame
	*(s.p++) = CRYPTO;
	s.p = encode_varint(s.p, tx->offset);
	s.p += 2; // fill out later
	uint8_t *crypto_begin = s.p;

	// TLS record header
	*(s.p++) = SERVER_HELLO;
	s.p += 3; // fill out later
	uint8_t *hello_begin = s.p;

	if (encode_server_hello(&s, &sh)) {
		return -1;
	}

	uint16_t hello_len = (uint16_t)(s.p - hello_begin);
	uint16_t crypto_len = (uint16_t)(s.p - crypto_begin);

	s.p += QUIC_TAG_SIZE;
	uint8_t *pkt_end = s.p;

	// fill out sizes
	write_big_24(hello_begin - 3, hello_len);
	write_big_16(crypto_begin - 2, VARINT_16 | crypto_len);
	write_big_16(packet_number - 2, VARINT_16 | (uint16_t)(pkt_end - packet_number));

	// encrypt
	encrypt_packet(&c->tkey[QC_INITIAL], tx->next, pkt_begin, packet_number, enc_begin, pkt_end);

	if (c->tx_crypto_len + crypto_len > sizeof(c->tx_crypto_data)) {
		return -1;
	}

	// send
	tick_t sent;
	if (c->send(c->user, pkt_begin, pkt_end - pkt_begin, (struct sockaddr*)&c->peer_addr->ss, c->peer_addr->len, &sent)) {
		return -1;
	}

	memcpy(c->tx_crypto_data + c->tx_crypto_len, crypto_begin, crypto_len);
	c->tx_crypto_len += crypto_len;
	tx->offsets[tx->next] = tx->offset;
	tx->offset += crypto_len;
	tx->next++;
	return 0;
}

static br_ec_private_key *find_private_key(qconnection_t *c, int curve) {
	for (size_t i = 0; i < c->key_num; i++) {
		if (c->priv_key[i].curve == curve) {
			return &c->priv_key[i];
		}
	}
	return NULL;
}

static int send_client_finished(qconnection_t *c, struct server_hello *sh, qslice_t shraw) {
	br_ec_private_key *sk = find_private_key(c, sh->key.curve);
	if (!sk || init_message_hash(&c->tls_hash, sh->cipher)) {
		return -1;
	}

	c->tls_hash.vtable->update(&c->tls_hash.vtable, c->tx_crypto_data, c->tx_crypto_len);
	c->tls_hash.vtable->update(&c->tls_hash.vtable, shraw.p, shraw.e - shraw.p);

	if (generate_handshake_secrets(&c->tls_hash.vtable, &sh->key, sk, sh->cipher,
		&c->tkey[QC_HANDSHAKE], &c->rkey[QC_HANDSHAKE], c->master_secret)) {
		return -1;
	}

	return 0;
}

static int update_crypto_buffer(qrx_crypto_t *b, enum qcrypto_level level, qslice_t *s) {
	int64_t off = decode_varint(s);
	int64_t len = decode_varint(s);
	if (off < 0 || len < 0 || (int64_t)(s->e - s->p) < len) {
		return -1;
	}
	if (level > b->level && !off) {
		// we've increased our crypto level
		b->level = level;
		b->off = 0;
		b->used = b->have = 0;
	} else if (level != b->level || (uint64_t)off != b->off) {
		// out of order packet, don't ack the packet
		// so we get it later once it's in order
		return -1;
	}

	size_t sz = (size_t)len;
	size_t have = b->have - b->used;
	if (have + sz > sizeof(b->buffer)) {
		// too much data
		return -1;
	} else if (have) {
		// compact the remaining buffer from last time
		// and add the new data
		memmove(b->buffer, b->buffer + b->used, have);
		memcpy(b->buffer + have, s->p, sz);
		b->used = 0;
		b->have = have + sz;
		b->ptr = NULL;
		b->end = NULL;
	} else {
		b->ptr = s->p;
		b->end = s->p + sz;
	}

	s->p += sz;
	b->off = off + sz;
	return 0;
}

static int peek_crypto_buffer(qrx_crypto_t *b, size_t need, qslice_t *s) {
	if (b->ptr + need <= b->end) {
		// can service from the saved pointer
		s->p = b->ptr;
		s->e = s->p + need;
		return 0;
	} else if (b->used + need <= b->have) {
		// can service from the buffer
		s->p = b->buffer + b->used;
		s->e = s->p + need;
		return 0;
	} else {
		if (b->ptr < b->end) {
			// store the data away for next time
			b->used = 0;
			b->have = b->end - b->ptr;
			memcpy(b->buffer, b->ptr, b->have);
		}
		b->ptr = b->end = NULL;
		return -1;
	}
}

static bool next_tls_record(qrx_crypto_t *b, uint8_t *ptype, qslice_t *data) {
	qslice_t tls_data;
	if (peek_crypto_buffer(b, 4, &tls_data)) {
		return false;
	}
	uint8_t tls_type = tls_data.p[0];
	uint32_t tls_len = big_24(tls_data.p + 1);
	if (peek_crypto_buffer(b, 4 + tls_len, data)) {
		return false;
	}
	*ptype = tls_type;

	if (b->ptr) {
		b->ptr += 4 + tls_len;
	} else {
		b->used += 4 + tls_len;
	}
	return true;
}

static uint8_t *find_non_padding(uint8_t *p, uint8_t *e) {
	while (p < e && *p == PADDING) {
		p++;
	}
	return p;
}

static int process_initial_server(qconnection_t *c, qslice_t s) {
	while (s.p < s.e) {
		switch (*(s.p++)) {
		default:
			return -1;
		case PADDING:
			s.p = find_non_padding(s.p, s.e);
			break;
		case CRYPTO: {
			if (update_crypto_buffer(&c->rx_crypto, QC_INITIAL, &s)) {
				return -1;
			}
			uint8_t type;
			qslice_t data;
			while (next_tls_record(&c->rx_crypto, &type, &data)) {
				switch (type) {
				case CLIENT_HELLO: {
					struct client_hello ch;
					if (decode_client_hello(data, &ch)) {
						LOG(c->debug, "client hello parse failure");
					} else {
						send_server_hello(c, &ch);
					}
					break;
				}
				}
			}
			break;
		}
		}
	}

	return 0;
}

static int process_initial_client(qconnection_t *c, qslice_t s) {
	while (s.p < s.e) {
		switch (*(s.p++)) {
		default:
			return -1;
		case PADDING:
			s.p = find_non_padding(s.p, s.e);
			break;
		case CRYPTO: {
			if (update_crypto_buffer(&c->rx_crypto, QC_INITIAL, &s)) {
				return -1;
			}
			uint8_t type;
			qslice_t data;
			while (next_tls_record(&c->rx_crypto, &type, &data)) {
				switch (type) {
				case SERVER_HELLO: {
					struct server_hello sh;
					if (decode_server_hello(data, &sh)) {
						LOG(c->debug, "server hello parse failure");
					} else {
						send_client_finished(c, &sh, data);
					}
				}
				}
			}
			break;
		}
		}
	}
	return 0;
}

static int process_handshake_client(qconnection_t *c, qslice_t data) {
	return 0;
}

static int process_handshake_server(qconnection_t *c, qslice_t data) {
	return 0;
}

static int process_protected(qconnection_t *c, qslice_t data) {
	return 0;
}

static int process_packet(qconnection_t *c, qslice_t data, enum qcrypto_level level) {
	switch (level) {
	case QC_HANDSHAKE:
		return c->is_client ? process_handshake_client(c, data) : process_handshake_server(c, data);
	case QC_INITIAL:
		return c->is_client ? process_initial_client(c, data) : process_initial_server(c, data);
	default:
		return process_protected(c, data);
	}
}

int qc_on_recv(qconnection_t *c, void *buf, size_t len, const struct sockaddr *sa, size_t salen, tick_t rxtime) {
	qslice_t s;
	s.p = buf;
	s.e = s.p + len;

	while (s.p < s.e) {
		uint8_t *pkt_begin = s.p;
		uint8_t hdr = *(s.p++);
		if (hdr & LONG_HEADER_FLAG) {
			if (s.e - s.p < 5) {
				return -1;
			}
			uint32_t version = big_32(s.p);
			s.p += 4;
			if (version != QUIC_VERSION) {
				// TODO send version negotiation
				// and handle version negotiation
				return -1;
			}
			uint8_t dcil = decode_id_len(s.p[0] >> 4);
			uint8_t scil = decode_id_len(s.p[0] & 0xF);
			s.p++;
			if (dcil != DEFAULT_SERVER_ID_LEN) {
				return -1;
			}

			if (!c->is_client && !c->local_id) {
				c->local_id = &c->local_ids[0];
				c->local_id->len = dcil;
				memcpy(c->local_id->id, s.p, dcil);
				s.p += dcil;
				c->peer_id = &c->peer_ids[0];
				c->peer_id->len = scil;
				memcpy(c->peer_id->id, s.p, scil);
				s.p += scil;

				generate_initial_secrets(c->local_id, &c->rkey[QC_INITIAL], &c->tkey[QC_INITIAL]);
			} else {
				s.p += dcil + scil;
			}

			enum qcrypto_level level;
			switch (hdr) {
			case INITIAL_PACKET: {
				level = QC_INITIAL;
				int64_t toksz = decode_varint(&s);
				if (toksz < 0 || toksz >(int64_t)(s.e - s.p)) {
					return -1;
				}
				s.p += (size_t)toksz; // skip over token
				break;
			}
			case HANDSHAKE_PACKET:
				level = QC_HANDSHAKE;
				break;
			case PROTECTED_PACKET:
				level = QC_PROTECTED;
				break;
			default:
				// TODO handle RETRY
				return -1;
			}

			int64_t paysz = decode_varint(&s);
			if (paysz < 0 || paysz > (int64_t)(s.e - s.p)) {
				return -1;
			}
			uint8_t *packet_number = s.p;
			s.p += paysz;

			qslice_t data;
			int64_t pktnum = decrypt_packet(&c->rkey[level], pkt_begin, packet_number, s.p, &data);
			if (pktnum < 0) {
				return -1;
			}

			if (process_packet(c, data, level)) {
				return -1;
			}

		} else {
			// short header
			s.p += DEFAULT_SERVER_ID_LEN;
			if (s.p > s.e) {
				return -1;
			}
			qslice_t data;
			int64_t pktnum = decrypt_packet(&c->rkey[QC_PROTECTED], pkt_begin, s.p, s.e, &data);
			if (pktnum < 0) {
				return -1;
			}

			return process_protected(c, data);
		}
	}

	return 0;
}
