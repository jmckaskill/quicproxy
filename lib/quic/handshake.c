#include "internal.h"

// TLS records
#define TLS_RECORD_HEADER_SIZE 4
#define TLS_CLIENT_HELLO 1
#define TLS_SERVER_HELLO 2
#define TLS_NEW_SESSION_TICKET 4
#define TLS_END_OF_EARLY_DATA 5
#define TLS_ENCRYPTED_EXTENSIONS 8
#define TLS_CERTIFICATE 11
#define TLS_CERTIFICATE_REQUEST 13
#define TLS_CERTIFICATE_VERIFY 15
#define TLS_FINISHED 20
#define TLS_KEY_UPDATE 24
#define TLS_MESSAGE_HASH 254

#define TLS_LEGACY_VERSION 0x303
#define TLS_VERSION_GREASE 0x7A7A

#define EC_KEY_UNCOMPRESSED 4
#define GROUP_GREASE 0x3A3A
#define KEY_SHARE_GREASE 0x9A9A
#define SIG_GREASE 0x6A6A
#define CIPHER_GREASE 0x8A8A

// TLS compression methods
#define TLS_COMPRESSION_NULL 0


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
#define EXTENSION_GREASE 0x4A4A
#define QUIC_TRANSPORT_PARAMETERS 0xFFA5

#define TP_stream_data_bidi_local 0x00
#define TP_max_data 0x01
#define TP_bidi_streams 0x02
#define TP_idle_timeout 0x03
#define TP_preferred_address 0x04
#define TP_max_packet_size 0x05
#define TP_stateless_reset_token 0x06
#define TP_ack_delay_exponent 0x07
#define TP_uni_streams 0x08
#define TP_disable_migration 0x09
#define TP_stream_data_bidi_remote 0x0A
#define TP_stream_data_uni 0x0B
#define TP_max_ack_delay 0x0C
#define TP_original_connection_id 0x0D
#define TP_grease 0x5A5A

// server name
#define HOST_NAME_TYPE 0
#define NAME_GREASE 0xAA

uint8_t *q_encode_varint(uint8_t *p, uint64_t val) {
	if (val < 0x40) {
		*(p++) = (uint8_t)val;
		return p;
	} else if (val < 0x4000) {
		return write_big_16(p, (uint16_t)val | VARINT_16);
	} else if (val < 0x40000000) {
		return write_big_32(p, (uint32_t)val | VARINT_32);
	} else {
		return write_big_64(p, val | VARINT_64);
	}
}

int q_decode_varint(qslice_t *s, uint64_t *pval) {
	if (s->p == s->e) {
		return -1;
	}
	uint8_t *p = s->p++;
	uint8_t hdr = *p;
	switch (hdr >> 6) {
	case 0:
		*pval = hdr;
		return 0;
	case 1:
		if (s->p == s->e) {
			return -1;
		}
		*pval = (((uint16_t)hdr & 0x3F) << 8) | *(s->p++);
		return 0;
	case 2:
		if (s->p + 3 > s->e) {
			return -1;
		}
		s->p += 3;
		*pval = big_32(p) & UINT32_C(0x3FFFFFFF);
		return 0;
	default:
		if (s->p + 7 > s->e) {
			return -1;
		}
		s->p += 7;
		*pval = big_64(p) & UINT64_C(0x3FFFFFFFFFFFFFFF);
		return 0;
	}
}

uint8_t *q_encode_packet_number(uint8_t *p, uint64_t base, uint64_t val) {
	assert(val >= base);
	uint32_t diff = (uint32_t)(val - base);
	if (diff < 0x40) {
		*p++ = (uint8_t)(val & 0x7F);
	} else if (diff < 0x2000) {
		*p++ = ((uint8_t)(val >> 8) & 0x3F) | 0x80;
		*p++ = (uint8_t)(val);
	} else {
		*p++ = ((uint8_t)(val >> 24) & 0x3F) | 0xC0;
		*p++ = (uint8_t)(val >> 16);
		*p++ = (uint8_t)(val >> 8);
		*p++ = (uint8_t)val;
	}
	return p;
}

uint8_t *q_decode_packet_number(uint8_t *p, uint64_t base, uint64_t *pval) {
	unsigned shift;
	uint32_t raw = *p++;

	switch (raw >> 6) {
	default:
		raw &= 0x7F;
		shift = 32 - 7;
		break;
	case 2:
		raw = (raw & 0x3F) << 8;
		raw |= (uint32_t)*(p++);
		shift = 32 - 14;
		break;
	case 3:
		raw = (raw & 0x3F) << 24;
		raw |= (uint32_t)*(p++) << 16;
		raw |= (uint32_t)*(p++) << 8;
		raw |= (uint32_t)*(p++);
		shift = 32 - 30;
		break;
	}

	// raw = original mod n
	// if n is chosen such that
	// (original - base) signed mod n = original - base
	// then
	// diff = (raw - base) signed mod n = original - base
	// original = base + diff

	raw <<= shift;
	uint32_t base_shifted = (uint32_t)base << shift;
	int32_t diff = (int32_t)(raw - base_shifted);
	diff >>= shift;
	*pval = base + diff;
	return p;
}

static int encode_transport(qslice_t *s, uint16_t parameter, uint32_t value, size_t sz) {
	if (s->p + 2+2+4 > s->e) {
		return -1;
	}
	s->p = write_big_16(s->p, parameter);
	s->p = write_big_16(s->p, (uint16_t)sz);
	switch (sz) {
	case 4:
		s->p = write_big_32(s->p, value);
		break;
	case 2:
		s->p = write_big_16(s->p, (uint16_t)value);
		break;
	case 1:
		*(s->p++) = (uint8_t)value;
		break;
	case 0:
		break;
	}
	return 0;
}

static int encode_transport_params(qslice_t *s, const qconnection_cfg_t *p, uint64_t orig_server_id) {
	if (s->p + 2 + 2 + 2 + 3 > s->e) {
		return -1;
	}
	s->p += 2;
	uint8_t *params_start = s->p;
	s->p = write_big_16(s->p, TP_grease);
	s->p = write_big_16(s->p, 3);
	s->p = write_big_24(s->p, 0);
	if (p->stream_data_bidi_local && encode_transport(s, TP_stream_data_bidi_local, p->stream_data_bidi_local, 4)) {
		return -1;
	}
	if (p->stream_data_bidi_remote && encode_transport(s, TP_stream_data_bidi_remote, p->stream_data_bidi_remote, 4)) {
		return -1;
	}
	if (p->stream_data_uni && encode_transport(s, TP_stream_data_uni, p->stream_data_uni, 4)) {
		return -1;
	}
	if (p->bidi_streams && encode_transport(s, TP_bidi_streams, p->bidi_streams, 2)) {
		return -1;
	}
	if (p->uni_streams && encode_transport(s, TP_uni_streams, p->uni_streams, 2)) {
		return -1;
	}
	if (p->max_data && encode_transport(s, TP_max_data, p->max_data, 4)) {
		return -1;
	}
	if (p->idle_timeout && encode_transport(s, TP_idle_timeout, p->idle_timeout / 1000000, 2)) {
		return -1;
	}
	if (p->max_packet_size && encode_transport(s, TP_max_packet_size, p->max_packet_size, 2)) {
		return -1;
	}
	if (p->disable_migration && encode_transport(s, TP_disable_migration, 0, 0)) {
		return -1;
	}
	if (p->ack_delay_exponent && encode_transport(s, TP_ack_delay_exponent, p->ack_delay_exponent, 1)) {
		return -1;
	}
	if (p->max_ack_delay && encode_transport(s, TP_max_ack_delay, p->max_ack_delay / 1000, 1)) {
		return -1;
	}
	if (orig_server_id) {
		if (s->p + 2 + 2 + 8 > s->e) {
			return -1;
		}
		s->p = write_big_16(s->p, TP_original_connection_id);
		s->p = write_big_16(s->p, 8);
		s->p = write_little_64(s->p, orig_server_id);
	}
	write_big_16(params_start - 2, (uint16_t)(s->p - params_start));
	return 0;
}

static int encode_server_hello(const struct server_handshake *sh, qslice_t *ps) {
	// check fixed size headers - up to and including extensions list size & tls version
	qslice_t s = *ps;
	if (s.p + 1 + 3 + 2 + QUIC_RANDOM_SIZE + 1 + 2 + 1 + 2 + 2 + 2 + 2 > s.e) {
		return -1;
	}

	// TLS header
	*(s.p++) = TLS_SERVER_HELLO;
	s.p += 3;
	uint8_t *record_begin = s.p;

	// legacy version
	s.p = write_big_16(s.p, TLS_LEGACY_VERSION);

	// random field
	s.p = append_mem(s.p, sh->h.server_random, QUIC_RANDOM_SIZE);

	// legacy session ID - not used in QUIC
	*(s.p++) = 0;

	// cipher
	s.p = write_big_16(s.p, sh->h.c.prot_tx.vtable->code);

	// compression method
	*(s.p++) = TLS_COMPRESSION_NULL;

	// extensions
	s.p += 2;
	uint8_t *list_start = s.p;

	// supported version
	if (s.p + 2 + 2 + 2 > s.e) {
		return -1;
	}
	s.p = write_big_16(s.p, SUPPORTED_VERSIONS);
	s.p = write_big_16(s.p, 2); // extension data size
	s.p = write_big_16(s.p, TLS_VERSION);

	// key share
	if (s.p + 2 + 2 + 2 + 2 + 1 + BR_EC_KBUF_PUB_MAX_SIZE > s.e) {
		return -1;
	}
	s.p = write_big_16(s.p, KEY_SHARE);
	s.p += 2;
	uint8_t *ext_start = s.p;
	s.p = write_big_16(s.p, (uint16_t)sh->sk.curve);
	s.p += 2;
	uint8_t *key_start = s.p;
	*(s.p++) = EC_KEY_UNCOMPRESSED;
	s.p += br_ec_compute_pub(br_ec_get_default(), NULL, s.p, &sh->sk);

	write_big_16(key_start - 2, (uint16_t)(s.p - key_start));
	write_big_16(ext_start - 2, (uint16_t)(s.p - ext_start));

	write_big_16(list_start-2, (uint16_t)(s.p - list_start));
	write_big_24(record_begin - 3, (uint32_t)(s.p - record_begin));
	ps->p = s.p;
	return 0;
}

static int encode_encrypted_extensions(const struct server_handshake *sh, qslice_t *ps) {
	const qconnection_cfg_t *cfg = sh->h.c.local_cfg;

	// check fixed size headers - up to and including extensions list size & tls version
	qslice_t s = *ps;
	if (s.p + 1 + 3 + 2 > s.e) {
		return -1;
	}

	// TLS header
	*(s.p++) = TLS_ENCRYPTED_EXTENSIONS;
	s.p += 3;
	uint8_t *record_begin = s.p;

	// extensions list
	s.p += 2;
	uint8_t *list_start = s.p;

	// transport params
	if (s.p + 2 + 2 + 2 > s.e) {
		return -1;
	}
	s.p = write_big_16(s.p, QUIC_TRANSPORT_PARAMETERS);
	s.p += 2;
	uint8_t *transport_start = s.p;
	// negotiated version
	s.p = write_big_32(s.p, sh->h.c.version);
	// supported versions
	uint8_t *versions_start = ++s.p;
	const uint32_t *ver = cfg->versions ? cfg->versions : QUIC_VERSIONS;
	while (*ver) {
		if (s.p + 4 > s.e) {
			return -1;
		}
		s.p = write_big_32(s.p, *ver);
		ver++;
	}
	versions_start[-1] = (uint8_t)(s.p - versions_start);
	if (encode_transport_params(&s, cfg, sh->h.orig_server_id)) {
		return -1;
	}
	write_big_16(transport_start - 2, (uint16_t)(s.p - transport_start));

	write_big_16(list_start - 2, (uint16_t)(s.p - list_start));
	write_big_24(record_begin - 3, (uint32_t)(s.p - record_begin));
	ps->p = s.p;
	return 0;
}

static int encode_client_hello(const struct client_handshake *ch, qslice_t *ps) {
	const qconnection_cfg_t *cfg = ch->h.c.local_cfg;

	// check fixed entries - up to and including cipher list size
	qslice_t s = *ps;
	if (s.p + 4 + 2 + QUIC_RANDOM_SIZE + 1 + 2 + 2 > s.e) {
		return -1;
	}

	// TLS record
	*(s.p++) = TLS_CLIENT_HELLO;
	s.p += 3;
	uint8_t *record_begin = s.p;

	// legacy version
	s.p = write_big_16(s.p, TLS_LEGACY_VERSION);

	// random field
	memcpy(s.p, ch->h.c.client_random, QUIC_RANDOM_SIZE);
	s.p += QUIC_RANDOM_SIZE;

	// legacy session ID - not used in QUIC
	*(s.p++) = 0;

	// cipher suites
	s.p += 2;
	uint8_t *cipher_begin = s.p;
	s.p = write_big_16(s.p, CIPHER_GREASE);
	for (size_t i = 0; cfg->ciphers[i] != NULL; i++) {
		if (s.p + 2 > s.e) {
			return -1;
		}
		s.p = write_big_16(s.p, cfg->ciphers[i]->code);
	}
	write_big_16(cipher_begin - 2, (uint16_t)(s.p - cipher_begin));

	// compression methods
	if (s.p + 2 > s.e) {
		return -1;
	}
	*(s.p++) = 1;
	*(s.p++) = TLS_COMPRESSION_NULL;

	// extensions size in bytes - will fill out later
	if (s.p + 2 + 2 + 2 + 2 > s.e) {
		return -1;
	}
	s.p += 2;
	uint8_t *ext_start = s.p;
	s.p = write_big_16(s.p, EXTENSION_GREASE);
	s.p = write_big_16(s.p, 2);
	s.p = write_big_16(s.p, 0);

	// server name
	size_t name_len = strlen(ch->server_name);
	if (name_len) {
		if (s.p + 2+2+2+1+2+1+1+2+1+2 + name_len > s.e) {
			return -1;
		}
		s.p = write_big_16(s.p, SERVER_NAME);
		s.p = write_big_16(s.p, (uint16_t)(2+1+2+1+1+2+1+2 + name_len));
		s.p = write_big_16(s.p, (uint16_t)(1+2+1+1+2+1+2 + name_len));
		*(s.p++) = NAME_GREASE;
		s.p = write_big_16(s.p, 1);
		*(s.p++) = 0;
		*(s.p++) = HOST_NAME_TYPE;
		s.p = write_big_16(s.p, (uint16_t)name_len);
		s.p = append_mem(s.p, ch->server_name, name_len);
		*(s.p++) = NAME_GREASE;
		s.p = write_big_16(s.p, 0);
	}

	// supported groups
	if (s.p + 2 + 2 + 2 + 2*ch->key_num + 2 > s.e) {
		return -1;
	}
	s.p = write_big_16(s.p, SUPPORTED_GROUPS);
	s.p = write_big_16(s.p, (uint16_t)(2*ch->key_num) + 4);
	s.p = write_big_16(s.p, (uint16_t)(2*ch->key_num) + 2);
	s.p = write_big_16(s.p, GROUP_GREASE);
	for (size_t i = 0; i < ch->key_num; i++) {
		s.p = write_big_16(s.p, cfg->groups[i]);
	}

	// signature algorithms
	if (s.p + 2 + 4 + 2 > s.e) {
		return -1;
	}
	s.p = write_big_16(s.p, SIGNATURE_ALGORITHMS);
	s.p += 4;
	uint8_t *algo_start = s.p;
	s.p = write_big_16(s.p, SIG_GREASE);
	for (size_t i = 0; cfg->signatures[i] != NULL; i++) {
		if (s.p + 2 > s.e) {
			return -1;
		}
		s.p = write_big_16(s.p, cfg->signatures[i]->algorithm);
	}
	write_big_16(algo_start - 4, (uint16_t)(s.p - algo_start + 2));
	write_big_16(algo_start - 2, (uint16_t)(s.p - algo_start));

	// supported versions
	if (s.p + 2 + 2 + 1 + 2 + 2 > s.e) {
		return -1;
	}
	s.p = write_big_16(s.p, SUPPORTED_VERSIONS);
	s.p = write_big_16(s.p, 5); // extension length
	*(s.p++) = 4; // list of versions length
	s.p = write_big_16(s.p, TLS_VERSION_GREASE);
	s.p = write_big_16(s.p, TLS_VERSION);

	// key share
	if (s.p + 2 + 4 + 2 + 2 > s.e) {
		return -1;
	}
	s.p = write_big_16(s.p, KEY_SHARE);
	s.p += 4; // fill out the header later once we know the length
	uint8_t *keys_start = s.p;
	s.p = write_big_16(s.p, KEY_SHARE_GREASE);
	s.p = write_big_16(s.p, 0);
	const br_ec_impl *ec = br_ec_get_default();
	for (size_t i = 0; i < ch->key_num; i++) {
		if (s.p + 2 + 2 + 1 + BR_EC_KBUF_PUB_MAX_SIZE > s.e) {
			return -1;
		}
		br_ec_private_key sk;
		sk.curve = cfg->groups[i];
		sk.xlen = br_ec_keygen(NULL, ec, NULL, NULL, sk.curve);
		sk.x = (uint8_t*)&ch->keys[i * BR_EC_KBUF_PRIV_MAX_SIZE];

		s.p = write_big_16(s.p, cfg->groups[i]);
		s.p += 2;
		uint8_t *key_start = s.p;
		*(s.p++) = EC_KEY_UNCOMPRESSED;
		s.p += br_ec_compute_pub(ec, NULL, s.p, &sk);
		write_big_16(key_start - 2, (uint16_t)(s.p - key_start));
	}
	write_big_16(keys_start - 4, (uint16_t)(s.p - keys_start + 2));
	write_big_16(keys_start - 2, (uint16_t)(s.p - keys_start));

	// transport params
	if (s.p + 2 + 2 + 2 > s.e) {
		return -1;
	}
	s.p = write_big_16(s.p, QUIC_TRANSPORT_PARAMETERS);
	s.p += 2;
	uint8_t *transport_start = s.p;
	s.p = write_big_32(s.p, ch->initial_version ? ch->initial_version : ch->h.c.version);
	if (encode_transport_params(&s, cfg, 0)) {
		return -1;
	}
	write_big_16(transport_start - 2, (uint16_t)(s.p - transport_start));

	write_big_16(ext_start-2, (uint16_t)(s.p - ext_start));
	write_big_24(record_begin - 3, (uint32_t)(s.p - record_begin));
	ps->p = s.p;
	return 0;
}

static int encode_certificates(qslice_t *ps, const qsigner_class *const *signer) {
	qslice_t s = *ps;
	if (s.p + 4 + 1 + 3 > s.e) {
		return -1;
	}

	// TLS record
	*(s.p++) = TLS_CERTIFICATE;
	s.p += 3;
	uint8_t *record_begin = s.p;

	// request context
	*(s.p++) = 0;

	// cert list
	s.p += 3;
	uint8_t *list_begin = s.p;

	for (size_t i = 0;;i++) {
		const br_x509_certificate *c = (*signer)->get_cert(signer, i);
		if (!c) {
			break;
		} else if (s.p + 3 + c->data_len + 2 > s.e) {
			return -1;
		}
		s.p = write_big_24(s.p, (uint32_t)c->data_len);
		s.p = append_mem(s.p, c->data, c->data_len);
		s.p = write_big_16(s.p, 0); // extensions
	}

	write_big_24(list_begin - 3, (uint32_t)(s.p - list_begin));
	write_big_24(record_begin - 3, (uint32_t)(s.p - record_begin));
	ps->p = s.p;
	return 0;
}

static int encode_verify(qslice_t *ps, const qsignature_class *type, const void *sig, size_t len) {
	qslice_t s = *ps;
	if (s.p + 4 + 2 + 2 + len > s.e) {
		return -1;
	}

	// TLS record
	*(s.p++) = TLS_CERTIFICATE_VERIFY;
	s.p += 3;
	uint8_t *record_begin = s.p;

	// algorithm
	s.p = write_big_16(s.p, type->algorithm);

	// signature
	s.p = write_big_16(s.p, (uint16_t)len);
	s.p = append_mem(s.p, sig, len);

	write_big_24(record_begin - 3, (uint32_t)(s.p - record_begin));
	ps->p = s.p;
	return 0;
}

static size_t finished_len(const br_hash_class *digest) {
	return 4 + digest_size(digest);
}

uint8_t *q_encode_finished(struct connection *c, uint8_t *p) {
	const br_hash_class *hash = c->prot_rx.vtable->hash;
	*p++ = TLS_FINISHED;
	p = write_big_24(p, digest_size(hash));
	return append_mem(p, c->tx_finished, digest_size(hash));
}

const br_hash_class **init_message_hash(struct handshake *h) {
	const br_hash_class **msgs, *digest = h->c.prot_rx.vtable->hash;
	if (digest == &br_sha384_vtable) {
		msgs = &h->crypto.msg_sha384.vtable;
	} else {
		assert(digest == &br_sha256_vtable);
		msgs = &h->crypto.msg_sha256.vtable;
	}
	h->crypto.msgs = msgs;
	*msgs = h->c.prot_rx.vtable->hash;
	return msgs;
}

static int find_private_key(const char *curves, const uint8_t *keys, size_t key_num, int curve, br_ec_private_key *sk) {
	const br_ec_impl *ec = br_ec_get_default();
	for (size_t i = 0; i < key_num; i++) {
		if (curves[i] == curve) {
			sk->curve = curve;
			sk->xlen = br_ec_keygen(NULL, ec, NULL, NULL, curve);
			sk->x = (uint8_t*)&keys[i * BR_EC_KBUF_PRIV_MAX_SIZE];
			return 0;
		}
	}
	return -1;
}

static int init_handshake_keys(struct handshake *h, const br_hash_class **msgs, const br_ec_public_key *pk, const br_ec_private_key *sk) {
	uint8_t msg_hash[QUIC_MAX_HASH_SIZE];
	(*msgs)->out(msgs, msg_hash);
	if (calc_handshake_secret(h->hs_secret, *msgs, msg_hash, pk, sk)) {
		return -1;
	}
	uint8_t *client = (h->c.flags & QC_IS_SERVER) ? h->hs_rx : h->hs_tx;
	uint8_t *server = (h->c.flags & QC_IS_SERVER) ? h->hs_tx : h->hs_rx;
	derive_secret(client, *msgs, h->hs_secret, HANDSHAKE_CLIENT, msg_hash);
	derive_secret(server, *msgs, h->hs_secret, HANDSHAKE_SERVER, msg_hash);
	log_handshake(h->c.local_cfg->keylog, *msgs, client, server, h->c.client_random);
	return 0;
}

void init_protected_keys(struct handshake *h, const uint8_t *msg_hash) {
	const br_hash_class **msgs = h->crypto.msgs;
	struct connection *c = &h->c;
	uint8_t master[QUIC_MAX_HASH_SIZE], client[QUIC_MAX_HASH_SIZE], server[QUIC_MAX_HASH_SIZE];
	calc_master_secret(master, *msgs, h->hs_secret);
	derive_secret(client, *msgs, master, PROT_CLIENT, msg_hash);
	derive_secret(server, *msgs, master, PROT_SERVER, msg_hash);
	c->prot_rx.vtable->init(&c->prot_rx.vtable, (c->flags & QC_IS_SERVER) ? client : server);
	c->prot_tx.vtable->init(&c->prot_tx.vtable, (c->flags & QC_IS_SERVER) ? server : client);
	log_protected(c->local_cfg->keylog, *msgs, client, server, c->client_random);
}

static int check_signature(struct client_handshake *ch, uint16_t algorithm, const void *sig, size_t slen, const uint8_t *msg_hash) {
	const qsignature_class *type = find_signature(ch->h.c.local_cfg->signatures, algorithm);
	if (!type) {
		return QC_ERR_TLS_HANDSHAKE_FAILURE;
	}

	const br_hash_class **msgs = ch->h.crypto.msgs;
	uint8_t verify[QUIC_MAX_CERT_VERIFY_SIZE];
	size_t vlen = calc_cert_verify(verify, false, *msgs, msg_hash);

	unsigned usages;
	const br_x509_pkey *pk = (*ch->x509)->get_pkey(ch->x509, &usages);
	if (!(usages & BR_KEYTYPE_KEYX) || type->verify(type, pk, verify, vlen, sig, slen)) {
		return QC_ERR_TLS_HANDSHAKE_FAILURE;
	}
	return 0;
}

static int check_finish(struct handshake *h, const void *fin, const void *msg_hash) {
	uint8_t verify[QUIC_MAX_HASH_SIZE];
	const br_hash_class **msgs = h->crypto.msgs;
	calc_finish_verify(verify, *msgs, msg_hash, h->hs_rx);
	if (memcmp(fin, verify, digest_size(*msgs))) {
		return QC_ERR_TLS_HANDSHAKE_FAILURE;
	}
	return 0;
}


struct crypto_run {
	unsigned off;
	unsigned have;
	unsigned start;
	unsigned data_size;
	const uint8_t *base;
	const uint8_t *p;
};

static int getword(struct crypto_state *st, struct crypto_run *r, uint8_t need) {
	if (r->off + need > st->end) {
		return QC_ERR_TLS_DECODE_ERROR;
	} else if (r->off + need > r->have) {
		unsigned sz = r->have - r->off;
		memcpy(&st->buf[st->bufsz], r->base + r->off, sz);
		st->bufsz += (uint8_t)sz;
		return QC_MORE_DATA;
	} else if (!st->bufsz) {
		r->p = r->base + r->off;
		r->off += need;
		return 0;
	} else {
		unsigned sz = need - st->bufsz;
		memcpy(&st->buf[st->bufsz], r->base + r->off, sz);
		r->off += sz;
		r->p = st->buf;
		st->bufsz = 0;
		return 0;
	}
}

static int getbytes(struct crypto_state *st, struct crypto_run *r, void *dst, size_t need) {
	uint32_t have = st->have_bytes;
	need -= have;
	if (r->off + need > st->end) {
		return QC_ERR_TLS_DECODE_ERROR;
	} else if (r->off + need > r->have) {
		unsigned sz = r->have - r->off;
		memcpy((char*)dst + have, r->base + r->off, sz);
		st->have_bytes += sz;
		return QC_MORE_DATA;
	} else {
		memcpy((char*)dst + have, r->base + r->off, need);
		r->off += (unsigned)need;
		st->have_bytes = 0;
		return 0;
	}
}

static void update_msg_hash(struct crypto_state *st, struct crypto_run *r) {
	if (r->start < r->off) {
		if (st->msgs) {
			(*st->msgs)->update(st->msgs, r->base + r->start, r->off - r->start);
		} else {
			br_sha256_update(&st->msg_sha256, r->base + r->start, r->off - r->start);
			br_sha384_update(&st->msg_sha384, r->base + r->start, r->off - r->start);
		}
		r->start = r->off;
	}
}

#define CHECK_ROOT() assert(!st->depth && st->end == UINT32_MAX)
#define DO_POP() assert(st->depth); st->end = st->stack[--st->depth]; assert((st->stack[st->depth] = 0) == 0)
#define PUSH(SIZE) if (r.off + (SIZE) > st->end) {return QC_ERR_TLS_DECODE_ERROR;} else (assert(st->depth < ARRAYSZ(st->stack)), st->stack[st->depth++] = st->end, st->end = r.off + (SIZE))
#define POP(STATE) case STATE: if (r.have < st->end) {st->state = STATE; goto end;} else {r.off = st->end; DO_POP();} do{}while(0)

#define LOOP(NAME) loop_ ## NAME: if (r.off == st->end) { DO_POP(); goto after_ ## NAME; } else
#define LOOP_END(NAME) goto loop_ ## NAME; after_ ## NAME: do{}while(0)
#define LOOP_BREAK(NAME) goto after_ ## NAME;

#define GET_CHUNK(STATE) case STATE: if (r.off == r.have) {st->state = STATE; goto end;} else {unsigned data_off = r.off; r.off = MIN(r.have, st->end); r.p = r.base + data_off; r.data_size = r.off - data_off;} do{}while(0)
#define GET_1(STATE) case STATE: if (r.off == st->end) {return QC_ERR_TLS_DECODE_ERROR;} else if (r.off == r.have) {st->state = STATE; goto end;} else r.p = &r.base[r.off++]
#define GET_2(STATE) case STATE: if ((err = getword(st,&r,2)) != 0) {st->state = STATE; goto end;} else do{}while(0)
#define GET_3(STATE) case STATE: if ((err = getword(st,&r,3)) != 0) {st->state = STATE; goto end;} else do{}while(0)
#define GET_4(STATE) case STATE: if ((err = getword(st,&r,4)) != 0) {st->state = STATE; goto end;} else do{}while(0)
#define GET_8(STATE) case STATE: if ((err = getword(st,&r,8)) != 0) {st->state = STATE; goto end;} else do{}while(0)
#define GOTO_LEVEL(LEVEL,STATE) case STATE: if (level != (LEVEL)) {st->state = STATE; st->next = 0; st->level = (LEVEL); goto end;} else do{}while(0)
#define GET_BYTES(P,SZ,STATE) case STATE: if ((err = getbytes(st,&r,(P),(SZ))) != 0) {st->state = STATE; goto end;} else do{}while(0)

static int unpack_crypto_frame(struct crypto_state *st, struct crypto_run *r, enum qcrypto_level level, qslice_t *fd) {
	uint64_t off, len;
	if (q_decode_varint(fd, &off) || q_decode_varint(fd, &len) || len > (uint64_t)(fd->e - fd->p)) {
		return QC_ERR_FRAME_ENCODING;
	}
	const uint8_t *data = fd->p;
	fd->p += (size_t)len;

	if (!st || level < st->level || off + len <= (uint64_t)st->next) {
		// retransmit of old data
		return 0;
	} else if (level == st->level && off <= (uint64_t)st->next && off + len < UINT_MAX) {
		size_t shift = (size_t)(st->next - off);
		data += shift;
		len -= shift;
		off += shift;
	} else {
		// out of order data
		return QC_ERR_DROP;
	}

	r->off = (unsigned)off;
	r->start = r->off;
	r->have = r->off + (unsigned)len;
	r->base = data - r->off;
	st->next = r->have;
	return 0;
}

int q_decode_request_crypto(qconnect_request_t *req, qslice_t *fd) {
	struct crypto_state cst = { 0 }, *st = &cst;
	st->level = QC_INITIAL;
	st->end = UINT32_MAX;

	struct crypto_run r;
	int err = unpack_crypto_frame(&cst, &r, QC_INITIAL, fd);
	if (err) {
		return err;
	} else if (req->chello) {
		return QC_ERR_TLS_UNEXPECTED_MESSAGE;
	}

	bool have_tls_version = false;
	
	switch (REQUEST_START) {
	case REQUEST_START:
		CHECK_ROOT();
		GET_4(CHELLO_HEADER);
		if (r.p[0] != TLS_CLIENT_HELLO) {
			return QC_ERR_TLS_UNEXPECTED_MESSAGE;
		}
		PUSH(big_24(r.p + 1));
		GET_2(CHELLO_LEGACY_VERSION);
		if (big_16(r.p) != TLS_LEGACY_VERSION) {
			return QC_ERR_TLS_HANDSHAKE_FAILURE;
		}
		GET_BYTES(req->client_random, QUIC_RANDOM_SIZE, CHELLO_RANDOM);

		GET_1(CHELLO_LEGACY_SESSION);
		if (*r.p) {
			return QC_ERR_TLS_HANDSHAKE_FAILURE;
		}
		GET_2(CHELLO_CIPHER_LIST_SIZE);
		PUSH(big_16(r.p));
		LOOP(CHELLO_CIPHER_LIST) {
			GET_2(CHELLO_CIPHER);
			req->cipher = find_cipher(req->server_cfg->ciphers, big_16(r.p));
			if (req->cipher) {
				POP(CHELLO_CIPHER_LIST);
				goto chello_have_cipher;
			}
			LOOP_END(CHELLO_CIPHER_LIST);
		}
		return QC_ERR_TLS_HANDSHAKE_FAILURE;
	chello_have_cipher:
		GET_2(CHELLO_COMPRESSION);
		if (r.p[0] != 1 || r.p[1] != TLS_COMPRESSION_NULL) {
			return QC_ERR_TLS_HANDSHAKE_FAILURE;
		}
		GET_2(CHELLO_EXT_LIST_SIZE);
		PUSH(big_16(r.p));
		LOOP(CHELLO_EXT_LIST) {
			GET_4(CHELLO_EXT_HEADER);
			PUSH(big_16(r.p + 2));
			switch (big_16(r.p)) {
			case SERVER_NAME:
				goto ch_server_name;
			case SUPPORTED_VERSIONS:
				goto ch_supported_versions;
			case KEY_SHARE:
				goto ch_key_share;
			case SIGNATURE_ALGORITHMS:
				goto ch_signature_algorithms;
			case QUIC_TRANSPORT_PARAMETERS:
				goto ch_transport_parameters;
			default:
				goto finish_chello_extension;
			}
		ch_server_name:
			GET_2(CHELLO_NAME_LIST_SIZE);
			PUSH(big_16(r.p));
			LOOP(CHELLO_NAME_LIST) {
				GET_3(CHELLO_NAME_HEADER);
				if (r.p[0] == HOST_NAME_TYPE) {
					unsigned len = big_16(r.p + 1);
					if (!len || len + 1 > sizeof(req->server_name) || req->name_len) {
						return QC_ERR_TLS_HANDSHAKE_FAILURE;
					}
					req->name_len = len;
					GET_BYTES(req->server_name, req->name_len, CHELLO_NAME);
					req->server_name[req->name_len] = 0;
				} else {
					PUSH(big_16(r.p + 1));
					POP(CHELLO_NAME_IGNORE);
				}
				LOOP_END(CHELLO_NAME_LIST);
			}
			goto finish_chello_extension;
		ch_supported_versions:
			GET_1(CHELLO_VERSIONS_LIST_SIZE);
			PUSH(r.p[0]);
			LOOP(CHELLO_VERSIONS_LIST) {
				GET_2(CHELLO_VERSION);
				if (big_16(r.p) == TLS_VERSION) {
					have_tls_version = true;
				}
				LOOP_END(CHELLO_VERSIONS_LIST);
			}
			goto finish_chello_extension;
		ch_signature_algorithms:
			GET_2(CHELLO_ALGORITHMS_LIST_SIZE);
			PUSH(big_16(r.p));
			LOOP(CHELLO_ALGORITHMS_LIST) {
				GET_2(CHELLO_ALGORITHM);
				const qsignature_class *type = find_signature(req->server_cfg->signatures, big_16(r.p));
				if (type && type->curve < 64) {
					req->signatures |= UINT64_C(1) << type->curve;
				}
				LOOP_END(CHELLO_ALGORITHMS_LIST);
			}
			goto finish_chello_extension;
		ch_key_share:
			GET_2(CHELLO_KEY_LIST_SIZE);
			PUSH(big_16(r.p));
			LOOP(CHELLO_KEY_LIST) {
				GET_2(CHELLO_KEY_GROUP);
				req->key.curve = big_16(r.p);
				GET_2(CHELLO_KEY_SIZE);
				int curve = req->key.curve;
				unsigned keysz = big_16(r.p);
				PUSH(keysz);
				if (0 < keysz && keysz < BR_EC_KBUF_PUB_MAX_SIZE + 1 && 0 < curve && curve < 128 && strchr(req->server_cfg->groups, (char)curve)) {
					req->key.qlen = keysz - 1;
					GET_1(CHELLO_KEY_TYPE);
					if (r.p[0] == EC_KEY_UNCOMPRESSED) {
						GET_BYTES(req->key_data, req->key.qlen, CHELLO_KEY_DATA);
						req->key.q = req->key_data;
						POP(CHELLO_KEY);
						POP(CHELLO_KEY_LIST);
						goto finish_chello_extension;
					}
				}
				POP(CHELLO_KEY_IGNORE);
				LOOP_END(CHELLO_KEY_LIST);
			}
			return QC_ERR_TLS_HANDSHAKE_FAILURE;
		ch_transport_parameters:
			GET_4(CHELLO_TP_INITIAL_VERSION);
			// ignore initial version
			GET_2(CHELLO_TP_LIST_SIZE);
			PUSH(big_16(r.p));
			LOOP(CHELLO_TP_LIST) {
				GET_4(CHELLO_TP_HEADER);
				PUSH(big_16(r.p + 2));
				switch (big_16(r.p)) {
				default:
					goto ch_finish_tp;
				case TP_original_connection_id:
				case TP_stateless_reset_token:
				case TP_preferred_address:
					return QC_ERR_TRANSPORT_PARAMETER;
				case TP_stream_data_bidi_local:
					goto ch_stream_data_bidi_local;
				case TP_stream_data_bidi_remote:
					goto ch_stream_data_bidi_remote;
				case TP_stream_data_uni:
					goto ch_stream_data_uni;
				case TP_max_data:
					goto ch_max_data;
				case TP_bidi_streams:
					goto ch_bidi_streams;
				case TP_uni_streams:
					goto ch_uni_streams;
				case TP_idle_timeout:
					goto ch_idle_timeout;
				case TP_max_packet_size:
					goto ch_max_packet_size;
				case TP_ack_delay_exponent:
					goto ch_ack_delay_exponent;
				case TP_disable_migration:
					req->client_cfg.disable_migration = true;
					goto ch_finish_tp;
				case TP_max_ack_delay:
					goto ch_max_ack_delay;
				}
			ch_stream_data_bidi_local:
				GET_4(CHELLO_TP_stream_data_bidi_local);
				req->client_cfg.stream_data_bidi_local = big_32(r.p);
				goto ch_finish_tp;
			ch_stream_data_bidi_remote:
				GET_4(CHELLO_TP_stream_data_bidi_remote);
				req->client_cfg.stream_data_bidi_remote = big_32(r.p);
				goto ch_finish_tp;
			ch_stream_data_uni:
				GET_4(CHELLO_TP_stream_data_uni);
				req->client_cfg.stream_data_uni = big_32(r.p);
				goto ch_finish_tp;
			ch_max_data:
				GET_4(CHELLO_TP_max_data);
				req->client_cfg.max_data = big_32(r.p);
				goto ch_finish_tp;
			ch_bidi_streams:
				GET_2(CHELLO_TP_bidi_streams);
				req->client_cfg.bidi_streams = big_16(r.p);
				goto ch_finish_tp;
			ch_uni_streams:
				GET_2(CHELLO_TP_uni_streams);
				req->client_cfg.uni_streams = big_16(r.p);
				goto ch_finish_tp;
			ch_idle_timeout:
				GET_2(CHELLO_TP_idle_timeout);
				req->client_cfg.idle_timeout = 1000 * 1000 * (tickdiff_t)big_16(r.p);
				goto ch_finish_tp;
			ch_max_packet_size:
				GET_2(CHELLO_TP_max_packet_size);
				req->client_cfg.max_packet_size = big_16(r.p);
				goto ch_finish_tp;
			ch_ack_delay_exponent:
				GET_1(CHELLO_TP_ack_delay_exponent);
				req->client_cfg.ack_delay_exponent = r.p[0];
				goto ch_finish_tp;
			ch_max_ack_delay:
				GET_1(CHELLO_TP_max_ack_delay);
				req->client_cfg.max_ack_delay = 1000 * r.p[0];
				goto ch_finish_tp;
			ch_finish_tp:
				POP(CHELLO_TP);
				LOOP_END(CHELLO_TP_LIST);
			}
			goto finish_chello_extension;

		finish_chello_extension:
			POP(CHELLO_EXT);
			LOOP_END(CHELLO_EXT_LIST);
		}
		POP(CHELLO);
		CHECK_ROOT();
		if (!have_tls_version || !req->key.q || !req->name_len || !req->signatures) {
			return QC_ERR_TLS_HANDSHAKE_FAILURE;
		}

		req->chello = r.base;
		req->chello_size = r.off;

		return 0;
	}
end:
	return QC_ERR_TLS_HANDSHAKE_FAILURE;
}

// Besides the client hello, all other crypto packets are decoded by using the a resumable decoder
// This makes it a bit more complex, but means we don't have to buffer packet data.
int q_decode_handshake_crypto(struct connection *c, enum qcrypto_level level, qslice_t *fd, tick_t rxtime) {
	struct crypto_run r;
	struct handshake *h = (struct handshake*)c;
	struct client_handshake *ch = (struct client_handshake*)c;
	struct crypto_state *st = (c->flags & QC_HS_COMPLETE) ? NULL : &h->crypto;

	int err = unpack_crypto_frame(st, &r, level, fd);
	if (err || !st) {
		return err;
	}

	const br_hash_class **msgs = st->msgs;

	switch ((enum handshake_crypto_state)st->state) {

		// SERVER_HELLO

	case CLIENT_START:
		CHECK_ROOT();
		ch->u.sh.have_tls_version = false;
		ch->u.sh.k.curve = 0;
		ch->u.sh.k.qlen = 0;
		GET_4(SHELLO_HEADER);
		if (r.p[0] != TLS_SERVER_HELLO) {
			return QC_ERR_TLS_UNEXPECTED_MESSAGE;
		}
		PUSH(big_24(r.p+1));
		GET_2(SHELLO_LEGACY_VERSION);
		if (big_16(r.p) != TLS_LEGACY_VERSION) {
			return QC_ERR_TLS_HANDSHAKE_FAILURE;
		}
		PUSH(QUIC_RANDOM_SIZE);
		POP(SHELLO_RANDOM);
		GET_1(SHELLO_LEGACY_SESSION);
		if (*r.p) {
			return QC_ERR_TLS_HANDSHAKE_FAILURE;
		}
		GET_2(SHELLO_CIPHER);
		c->prot_tx.vtable = c->prot_rx.vtable = find_cipher(c->local_cfg->ciphers, big_16(r.p));
		if (!c->prot_tx.vtable) {
			return QC_ERR_TLS_HANDSHAKE_FAILURE;
		}
		GET_1(SHELLO_COMPRESSION);
		if (*r.p != TLS_COMPRESSION_NULL) {
			// only null compression is supported in TLS 1.3
			return QC_ERR_TLS_HANDSHAKE_FAILURE;
		}
		GET_2(SHELLO_EXT_LIST_SIZE);
		PUSH(big_16(r.p));

		LOOP(SHELLO_EXT_LIST) {
			GET_4(SHELLO_EXT_HEADER);
			PUSH(big_16(r.p + 2));
			switch (big_16(r.p)) {
			case KEY_SHARE:
				goto sh_key_share;
			case SUPPORTED_VERSIONS:
				goto sh_supported_version;
			default:
				goto finish_shello_extension;
			}

		sh_supported_version:
			GET_2(SHELLO_SUPPORTED_VERSION);
			if (big_16(r.p) == TLS_VERSION) {
				ch->u.sh.have_tls_version = true;
			}
			goto finish_shello_extension;

		sh_key_share:
			GET_2(SHELLO_KEY_GROUP);
			ch->u.sh.k.curve = big_16(r.p);
			GET_2(SHELLO_KEY_SIZE);
			ch->u.sh.k.qlen = big_16(r.p);
			if (!ch->u.sh.k.qlen) {
				// first byte is the key type
				return QC_ERR_TLS_HANDSHAKE_FAILURE;
			}
			ch->u.sh.k.qlen--;
			GET_1(SHELLO_KEY_TYPE);
			if (*r.p != EC_KEY_UNCOMPRESSED) {
				return QC_ERR_TLS_HANDSHAKE_FAILURE;
			}
			GET_BYTES(ch->u.sh.key_data, ch->u.sh.k.qlen, SHELLO_KEY_DATA);
			ch->u.sh.k.q = ch->u.sh.key_data;
			goto finish_shello_extension;

		finish_shello_extension:
			POP(SHELLO_FINISH_EXTENSION);
			LOOP_END(SHELLO_EXT_LIST);
		}

		POP(SHELLO);
		CHECK_ROOT();

		{
			if (!ch->u.sh.have_tls_version || !ch->u.sh.k.q) {
				return QC_ERR_TLS_HANDSHAKE_FAILURE;
			}
			msgs = init_message_hash(h);
			update_msg_hash(st, &r);

			br_ec_private_key sk;
			if (find_private_key(h->c.local_cfg->groups, ch->keys, ch->key_num, ch->u.sh.k.curve, &sk)) {
				return QC_ERR_TLS_HANDSHAKE_FAILURE;
			}
			if (init_handshake_keys(h, msgs, &ch->u.sh.k, &sk)) {
				return QC_ERR_TLS_HANDSHAKE_FAILURE;
			}
			c->flags |= QC_INIT_COMPLETE;
		}

		// ENCRYPTED_EXTENSIONS

		CHECK_ROOT();
		memset(&c->peer_cfg, 0, sizeof(c->peer_cfg));
		memset(&ch->u.ee, 0, sizeof(ch->u.ee));
		GOTO_LEVEL(QC_HANDSHAKE, EXTENSIONS_LEVEL);
		GET_4(EXTENSIONS_HEADER);
		if (r.p[0] != TLS_ENCRYPTED_EXTENSIONS) {
			return QC_ERR_TLS_UNEXPECTED_MESSAGE;
		}
		PUSH(big_24(r.p + 1));
		GET_2(EXTENSIONS_LIST_SIZE);
		PUSH(big_16(r.p));
		LOOP(EXTENSIONS_LIST) {
			GET_4(EXTENSIONS_EXT_HEADER);
			PUSH(big_16(r.p + 2));
			
			if (big_16(r.p) == QUIC_TRANSPORT_PARAMETERS) {
				// ignore negotiated & supported versions
				GET_4(EXTENSIONS_NEGOTIATED_VERSION);
				GET_1(EXTENSIONS_SUPPORTED_VERSIONS_SIZE);
				PUSH(r.p[0]);
				POP(EXTENSIONS_SUPPORTED_VERSIONS);

				GET_2(EXTENSIONS_TP_LIST_SIZE);
				PUSH(big_16(r.p));

				LOOP(EXTENSIONS_TP_LIST) {
					GET_4(EXTENSIONS_TP_KEY);
					PUSH(big_16(r.p + 2));
					switch (big_16(r.p)) {
					default:
						goto ee_finish_tp;
					case TP_stream_data_bidi_local:
						goto ee_stream_data_bidi_local;
					case TP_stream_data_bidi_remote:
						goto ee_stream_data_bidi_remote;
					case TP_stream_data_uni:
						goto ee_stream_data_uni;
					case TP_max_data:
						goto ee_max_data;
					case TP_bidi_streams:
						goto ee_bidi_streams;
					case TP_uni_streams:
						goto ee_uni_streams;
					case TP_idle_timeout:
						goto ee_idle_timeout;
					case TP_max_ack_delay:
						goto ee_max_ack_delay;
					case TP_ack_delay_exponent:
						goto ee_ack_delay_exponent;
					case TP_max_packet_size:
						goto ee_max_packet_size;
					case TP_original_connection_id:
						goto ee_original_connection_id;
					case TP_disable_migration:
						c->peer_cfg.disable_migration = true;
						goto ee_finish_tp;
					}
				ee_stream_data_bidi_local:
					GET_4(EXTENSIONS_TP_stream_data_bidi_local);
					c->peer_cfg.stream_data_bidi_local = big_32(r.p);
					goto ee_finish_tp;
				ee_stream_data_bidi_remote:
					GET_4(EXTENSIONS_TP_stream_data_bidi_remote);
					c->peer_cfg.stream_data_bidi_remote = big_32(r.p);
					goto ee_finish_tp;
				ee_stream_data_uni:
					GET_4(EXTENSIONS_TP_stream_data_uni);
					c->peer_cfg.stream_data_uni = big_32(r.p);
					goto ee_finish_tp;
				ee_bidi_streams:
					GET_2(EXTENSIONS_TP_bidi_streams);
					c->peer_cfg.bidi_streams = big_16(r.p);
					goto ee_finish_tp;
				ee_uni_streams:
					GET_2(EXTENSIONS_TP_uni_streams);
					c->peer_cfg.uni_streams = big_16(r.p);
					goto ee_finish_tp;
				ee_max_data:
					GET_4(EXTENSIONS_TP_max_data);
					c->peer_cfg.max_data = big_32(r.p);
					goto ee_finish_tp;
				ee_idle_timeout:
					GET_1(EXTENSIONS_TP_idle_timeout);
					c->peer_cfg.idle_timeout = 1000 * 1000 * (tickdiff_t)r.p[0];
					goto ee_finish_tp;
				ee_max_packet_size:
					GET_2(EXTENSIONS_TP_max_packet_size);
					c->peer_cfg.max_packet_size = big_16(r.p);
					goto ee_finish_tp;
				ee_ack_delay_exponent:
					GET_1(EXTENSIONS_TP_ack_delay_exponent);
					c->peer_cfg.ack_delay_exponent = r.p[0];
					goto ee_finish_tp;
				ee_max_ack_delay:
					GET_1(EXTENSIONS_TP_max_ack_delay);
					c->peer_cfg.max_ack_delay = 1000 * (tickdiff_t)big_16(r.p);
					goto ee_finish_tp;
				ee_original_connection_id:
					GET_8(EXTENSIONS_TP_original_connection_id);
					ch->u.ee.orig_server_id = little_64(r.p);
					goto ee_finish_tp;

				ee_finish_tp:
					POP(EXTENSIONS_TP);
					LOOP_END(EXTENSIONS_TP_LIST);
				}
			}
		
			POP(EXTENSIONS_EXT);
			LOOP_END(EXTENSIONS_LIST);
		}
		
		POP(EXTENSIONS);
		CHECK_ROOT();
		if (ch->u.ee.orig_server_id != h->orig_server_id) {
			return QC_ERR_TRANSPORT_PARAMETER;
		}

		// CERTIFICATE

		CHECK_ROOT();
		(*ch->x509)->start_chain(ch->x509, ch->server_name);
		GET_4(CERTIFICATE_HEADER);
		if (r.p[0] != TLS_CERTIFICATE) {
			return QC_ERR_TLS_UNEXPECTED_MESSAGE;
		}
		PUSH(big_24(r.p + 1));
		GET_1(CERTIFICATE_CONTEXT);
		if (*r.p != 0) {
			// QUIC does not support post handshake authentication
			// client authentication during the handshake must not use the request context
			return QC_ERR_TLS_HANDSHAKE_FAILURE;
		}
		GET_3(CERTIFICATE_LIST_SIZE);
		PUSH(big_24(r.p));


		LOOP(CERTIFICATE_LIST) {
			GET_3(CERTIFICATE_DATA_SIZE);
			PUSH(big_24(r.p));
			(*ch->x509)->start_cert(ch->x509, big_24(r.p));
			LOOP(CERTIFICATE_DATA) {
				GET_CHUNK(CERTIFICATE_DATA);
				(*ch->x509)->append(ch->x509, r.p, r.data_size);
				LOOP_END(CERTIFICATE_DATA);
			}
			(*ch->x509)->end_cert(ch->x509);
			// we don't support any extensions currently, so just skip over the data
			GET_2(CERTIFICATE_EXT_SIZE);
			PUSH(big_16(r.p));
			POP(CERTIFICATE_EXT);
			LOOP_END(CERTIFICATE_LIST);
		}

		POP(CERTIFICATE);
		CHECK_ROOT();

		switch ((*ch->x509)->end_chain(ch->x509)) {
		case 0:
			break;
		case BR_ERR_X509_CRITICAL_EXTENSION:
		case BR_ERR_X509_UNSUPPORTED:
			return QC_ERR_TLS_UNSUPPORTED_CERTIFICATE;
		case BR_ERR_X509_EXPIRED:
			return QC_ERR_TLS_CERTIFICATE_EXPIRED;
		case BR_ERR_X509_EMPTY_CHAIN:
		case BR_ERR_X509_BAD_SERVER_NAME:
			return QC_ERR_TLS_UNRECOGNIZED_NAME;
		case BR_ERR_X509_NOT_TRUSTED:
			return QC_ERR_TLS_UNKNOWN_CA;
		default:
			return QC_ERR_TLS_INTERNAL_ERROR;
		}

		// CERTIFICATE_VERIFY

		CHECK_ROOT();
		update_msg_hash(st, &r);
		(*msgs)->out(msgs, h->msg_hash);
		GET_4(VERIFY_HEADER);
		if (r.p[0] != TLS_CERTIFICATE_VERIFY) {
			return QC_ERR_TLS_UNEXPECTED_MESSAGE;
		}
		PUSH(big_24(r.p + 1));
		GET_2(VERIFY_ALGORITHM);
		ch->u.v.algorithm = big_16(r.p);
		GET_2(VERIFY_SIG_SIZE);
		ch->u.v.len = big_16(r.p);
		if (ch->u.v.len > sizeof(ch->u.v.sig)) {
			return QC_ERR_TLS_HANDSHAKE_FAILURE;
		}
		GET_BYTES(ch->u.v.sig, ch->u.v.len, VERIFY_SIG_DATA);
		POP(VERIFY);
		CHECK_ROOT();

		err = check_signature(ch, ch->u.v.algorithm, ch->u.v.sig, ch->u.v.len, h->msg_hash);
		if (err) {
			return err;
		}

		// FINISH
	case ACCEPT_START:
		CHECK_ROOT();
		update_msg_hash(st, &r);
		(*msgs)->out(msgs, h->msg_hash);
		GET_4(FINISHED_HEADER);
		if (r.p[0] != TLS_FINISHED) {
			return QC_ERR_TLS_UNEXPECTED_MESSAGE;
		} else if (big_24(r.p + 1) != digest_size(*msgs)) {
			return QC_ERR_TLS_HANDSHAKE_FAILURE;
		}
		GET_BYTES(h->rx_finished, digest_size(*msgs), FINISHED);
		CHECK_ROOT();

		err = check_finish(h, h->rx_finished, h->msg_hash);
		if (err) {
			return err;
		}

		// Post FINISH setup
		update_msg_hash(st, &r);
		if (c->flags & QC_IS_SERVER) {
			c->flags |= QC_HS_COMPLETE | QC_FIN_ACKNOWLEDGED;
			LOG(c->local_cfg->debug, "server handshake complete");
		} else {
			uint8_t msg_hash[QUIC_MAX_HASH_SIZE];
			(*msgs)->out(msgs, msg_hash);
			init_protected_keys(h, msg_hash);

			// add the client finished message to the message transcript
			// we will send it later with each outgoing message until the server acks one of them
			uint8_t fin[4];
			fin[0] = TLS_FINISHED;
			write_big_24(fin + 1, (uint32_t)digest_size(*msgs));
			calc_finish_verify(c->tx_finished, *msgs, msg_hash, h->hs_tx);
			(*msgs)->update(msgs, fin, 4);
			(*msgs)->update(msgs, c->tx_finished, digest_size(*msgs));

			// handshake is not complete until the server acks a packet containing the finished frame
			c->flags |= QC_HS_COMPLETE;
			LOG(c->local_cfg->debug, "generated client finished");
		}
		q_start_runtime_timers(h, rxtime);
		// Once we start the runtime, we no longer want to track handshake packets.
		return level == QC_HANDSHAKE ? QC_ERR_DROP : 0;
	}

end:
	if (err > 0) {
		return err;
	}
	update_msg_hash(st, &r);
	return 0;
}




///////////////////////////////
// Handshake

static qtx_packet_t *encode_long_packet(struct handshake *h, qslice_t *s, const qcipher_class **key, enum qcrypto_level level, uint64_t off, const void *crypto, size_t len, tick_t now) {
	struct connection *c = &h->c;
	struct server_handshake *sh = (struct server_handshake*)h;
	assert(!(c->flags & QC_HS_COMPLETE));
	assert(level <= QC_HANDSHAKE);
	qpacket_buffer_t *pkts = &h->pkts[level];

	if ((c->flags & QC_DRAINING) || pkts->tx_next >= pkts->tx_oldest + pkts->sent_len) {
		return NULL;
	} else if (s->p + 1 + 4 + 1 + 2 * QUIC_MAX_ADDRESS_SIZE + 1 + 2 + 4 + QUIC_TAG_SIZE > s->e) {
		return NULL;
	}

	qtx_packet_t *pkt = &pkts->sent[pkts->tx_next % pkts->sent_len];
	memset(pkt, 0, sizeof(*pkt));
	s->e -= QUIC_TAG_SIZE;

	// header
	uint8_t *pkt_begin = s->p;
	*(s->p++) = level == QC_INITIAL ? INITIAL_PACKET : HANDSHAKE_PACKET;
	s->p = write_big_32(s->p, c->version);

	// connection IDs
	*(s->p++) = (q_encode_id_len(c->peer_len) << 4);
	s->p = append_mem(s->p, c->peer_id, c->peer_len);
	if (c->flags & QC_IS_SERVER) {
		pkt_begin[5] |= q_encode_id_len(DEFAULT_SERVER_ID_LEN);
		s->p = append_mem(s->p, sh->server_id, DEFAULT_SERVER_ID_LEN);
	}

	// token
	if (level == QC_INITIAL) {
		if (c->flags & QC_IS_SERVER) {
			*(s->p++) = 0;
		} else {
			struct client_handshake *ch = (struct client_handshake*)h;
			s->p = q_encode_varint(s->p, ch->token_size);
			s->p = append_mem(s->p, ch->token, ch->token_size);
		}
	}

	// length
	s->p += 2;

	// packet number
	uint8_t *packet_number = s->p;
	s->p = q_encode_packet_number(s->p, pkts->tx_largest_acked, pkts->tx_next);
	uint8_t *enc_begin = s->p;

	if (c->flags & QC_CLOSING) {
		s->p = q_encode_close(c, s->p, s->e, !(c->flags & QC_IS_SERVER));
	} else {
		// ack frame
		s->p = q_encode_ack(pkts, s->p, now, QUIC_ACK_DELAY_SHIFT);

		// crypto frame
		if (len) {
			uint16_t chdr = 1 + 4 + 4;
			if (s->p + chdr + QUIC_TAG_SIZE > s->e) {
				return NULL;
			}
			uint16_t sz = (uint16_t)MIN(len, (size_t)(s->e - s->p) - chdr);
			*(s->p++) = CRYPTO;
			s->p = q_encode_varint(s->p, off);
			s->p = q_encode_varint(s->p, sz);
			s->p = append_mem(s->p, crypto, sz);
			pkt->off = off;
			pkt->len = sz;
		}

		// padding
		if (level == QC_INITIAL && !(c->flags & QC_IS_SERVER)) {
			s->p = append_bytes(s->p, 0, (size_t)(s->e - s->p));
		}
	}

	// tag
	uint8_t *tag = s->p;
	s->p += QUIC_TAG_SIZE;
	s->e += QUIC_TAG_SIZE;

	// fill out length
	write_big_16(packet_number - 2, VARINT_16 | (uint16_t)(s->p - packet_number));

	(*key)->encrypt(key, pkts->tx_next, pkt_begin, (size_t)(enc_begin - pkt_begin), enc_begin, tag);
	(*key)->protect(key, packet_number, (size_t)(enc_begin - packet_number), (size_t)(s->p - packet_number));
	return pkt;
}

void q_send_handshake_close(struct connection *c) {
	struct handshake *h = (struct handshake*)c;
	struct server_handshake *sh = (struct server_handshake*)c;
	// If we are shutting down during the handshake it's one of the following cases
	// 1. Server doesn't like the client hello - handled by qc_reject (no connection created)
	// 2. Client doesn't like the server hello - only has initial
	// 3. Client doesn't like the encrypted extensions - has handshake
	// 4. Server doesn't like the client finished (or doesn't receive it). Server has protected, but
	//    not sure if the client has handshake or protected keys. Use initial.

	uint8_t buf[DEFAULT_PACKET_SIZE];
	qslice_t s = { buf, buf + sizeof(buf) };
	qtx_packet_t *pkt;
	if (c->flags & QC_HS_RECEIVED) {
		qcipher_compat hk;
		c->prot_rx.vtable->init(&hk.vtable, h->hs_tx);
		pkt = encode_long_packet(h, &s, &hk.vtable, QC_HANDSHAKE, 0, NULL, 0, 0);
	} else if (c->flags & QC_IS_SERVER) {
		qcipher_aes_gcm key;
		init_initial_cipher(&key, true, sh->server_id, DEFAULT_SERVER_ID_LEN);
		pkt = encode_long_packet(h, &s, &key.vtable, QC_INITIAL, 0, NULL, 0, 0);
	} else {
		qcipher_aes_gcm key;
		init_initial_cipher(&key, false, c->peer_id, c->peer_len);
		pkt = encode_long_packet(h, &s, &key.vtable, QC_INITIAL, 0, NULL, 0, 0);
	}
	if (pkt) {
		(*c->iface)->send(c->iface, buf, (size_t)(s.p - buf), (struct sockaddr*)&c->addr, c->addr_len, &pkt->sent);
	}
}

qtx_packet_t *q_send_client_hello(struct client_handshake *ch, const br_prng_class **rand, tick_t now) {
	struct handshake *h = &ch->h;
	struct connection *c = &h->c;

	if (rand) {
		(*rand)->generate(rand, c->client_random, sizeof(c->client_random));
	}

	// encode the TLS record
	uint8_t tlsbuf[1024];
	qslice_t tls = { tlsbuf, tlsbuf + sizeof(tlsbuf) };
	if (encode_client_hello(ch, &tls)) {
		return NULL;
	}

	if (rand) {
		br_sha256_init(&h->crypto.msg_sha256);
		br_sha256_update(&h->crypto.msg_sha256, tlsbuf, tls.p - tlsbuf);
		br_sha384_init(&h->crypto.msg_sha384);
		br_sha384_update(&h->crypto.msg_sha384, tlsbuf, tls.p - tlsbuf);
	}

	qcipher_aes_gcm key;
	init_initial_cipher(&key, STREAM_CLIENT, c->peer_id, c->peer_len);

	// encode the UDP packet
	uint8_t udpbuf[DEFAULT_PACKET_SIZE];
	qslice_t udp = { udpbuf, udpbuf + sizeof(udpbuf) };
	qtx_packet_t *pkt = encode_long_packet(h, &udp, &key.vtable, QC_INITIAL, 0, tlsbuf, (size_t)(tls.p - tlsbuf), now);
	if (pkt == NULL) {
		return NULL;
	}

	// send it
	LOG(c->local_cfg->debug, "TX CLIENT HELLO");
	if ((*c->iface)->send(c->iface, udpbuf, (size_t)(udp.p - udpbuf), (struct sockaddr*)&c->addr, c->addr_len, &pkt->sent)) {
		return NULL;
	}

	h->pkts[QC_INITIAL].tx_next++;
	return pkt;
}

int q_send_server_hello(struct server_handshake *sh, const br_prng_class **rand, const br_ec_public_key *pk, tick_t now) {
	struct handshake *h = &sh->h;
	struct connection *c = &h->c;

	bool first_time = rand != NULL;
	if (first_time) {
		(*rand)->generate(rand, sh->server_random, sizeof(sh->server_random));
	}

	// server hello
	uint8_t tlsbuf[3 * 1024];
	qslice_t s = { tlsbuf, tlsbuf + sizeof(tlsbuf) };
	if (encode_server_hello(sh, &s)) {
		return -1;
	}
	size_t init_len = (size_t)(s.p - tlsbuf);
	const br_hash_class **msgs = h->crypto.msgs;

	if (first_time) {
		(*msgs)->update(msgs, tlsbuf, init_len);
		if (init_handshake_keys(h, msgs, pk, &sh->sk)) {
			return -1;
		}
	}

	// EncryptedExtensions
	uint8_t *ext_begin = s.p;
	if (encode_encrypted_extensions(sh, &s)) {
		return -1;
	}
	if (first_time) {
		(*msgs)->update(msgs, ext_begin, s.p - ext_begin);
	}

	// Certificate
	uint8_t *cert_begin = s.p;
	if (encode_certificates(&s, sh->signer)) {
		return -1;
	}
	if (first_time) {
		(*msgs)->update(msgs, cert_begin, s.p - cert_begin);
		(*msgs)->out(msgs, sh->cert_msg_hash);
	}

	// CertificateVerify
	uint8_t verify[QUIC_MAX_CERT_VERIFY_SIZE];
	size_t vlen = calc_cert_verify(verify, false, *msgs, sh->cert_msg_hash);
	uint8_t sig[QUIC_MAX_SIG_SIZE];
	uint8_t *verify_begin = s.p;
	int slen = (*sh->signer)->sign(sh->signer, sh->signature, verify, vlen, sig);
	if (slen < 0 || encode_verify(&s, sh->signature, sig, (size_t)slen)) {
		return -1;
	}

	// Finished
	if (first_time) {
		uint8_t msg_hash[QUIC_MAX_HASH_SIZE];
		(*msgs)->update(msgs, verify_begin, s.p - verify_begin);
		(*msgs)->out(msgs, msg_hash);
		calc_finish_verify(c->tx_finished, *msgs, msg_hash, h->hs_tx);
	}
	if (s.p + finished_len(*msgs) > s.e) {
		return -1;
	}
	s.p = q_encode_finished(c, s.p);
	if (first_time) {
		uint8_t msg_hash[QUIC_MAX_HASH_SIZE];
		(*msgs)->update(msgs, s.p - finished_len(*msgs), finished_len(*msgs));
		(*msgs)->out(msgs, msg_hash);
		init_protected_keys(h, msg_hash);
	}

	qcipher_aes_gcm ik;
	qcipher_compat hk;
	init_initial_cipher(&ik, STREAM_SERVER, sh->server_id, DEFAULT_SERVER_ID_LEN);
	c->prot_tx.vtable->init(&hk.vtable, h->hs_tx);

	// try and combine both initial and handshake into the same udp packet and send them
	size_t hs_len = (size_t)(s.p - ext_begin);
	size_t init_sent = 0;
	size_t hs_sent = 0;

	while (init_sent < init_len || hs_sent < hs_len) {
		uint8_t udpbuf[DEFAULT_PACKET_SIZE];
		qslice_t udp = { udpbuf, udpbuf + sizeof(udpbuf) };
		qtx_packet_t *ipkt = NULL, *hpkt = NULL;
		if (init_sent < init_len) {
			ipkt = encode_long_packet(h, &udp, &ik.vtable, QC_INITIAL, init_sent, tlsbuf + init_sent, init_len - init_sent, now);
		}
		if (hs_sent < hs_len) {
			hpkt = encode_long_packet(h, &udp, &hk.vtable, QC_HANDSHAKE, hs_sent, ext_begin + hs_sent, hs_len - hs_sent, now);
		}
		if (!ipkt && !hpkt) {
			return -1;
		}
		if ((*c->iface)->send(c->iface, udpbuf, (size_t)(udp.p - udpbuf), (struct sockaddr*)&c->addr, c->addr_len, &now)) {
			return -1;
		}
		if (ipkt) {
			init_sent += ipkt->len;
			ipkt->sent = now;
			h->pkts[QC_INITIAL].tx_next++;
		}
		if (hpkt) {
			hs_sent += hpkt->len;
			hpkt->sent = now;
			h->pkts[QC_HANDSHAKE].tx_next++;
		}
	}

	return 0;
}

