#include "packets.h"
#include "quic.h"
#include <cutils/endian.h>
#include <stdbool.h>


uint8_t encode_id_len(uint8_t len) {
	return len ? (len - 3) : 0;
}

uint8_t decode_id_len(uint8_t val) {
	return val ? (val + 3) : 0;
}

uint8_t *encode_varint(uint8_t *p, uint64_t val) {
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

int64_t decode_varint(qslice_t *s) {
	if (s->p == s->e) {
		return -1;
	}
	uint8_t *p = s->p++;
	uint8_t hdr = *p;
	switch (hdr >> 6) {
	case 0:
		return hdr;
	case 1:
		if (s->p == s->e) {
			return -1;
		}
		return (((uint16_t)hdr & 0x3F) << 8) | *(s->p++);
	case 2:
		if (s->p + 3 > s->e) {
			return -1;
		}
		s->p += 3;
		return big_32(p) & UINT32_C(0x3FFFFFFF);
	default:
		if (s->p + 7 > s->e) {
			return -1;
		}
		s->p += 7;
		return big_64(p) & UINT64_C(0x3FFFFFFFFFFFFFFF);
	}
}

size_t packet_number_length(uint64_t val) {
	return 4;
}

uint8_t *encode_packet_number(uint8_t *p, uint64_t val) {
	// TODO use base correctly
	return write_big_32(p, (uint32_t)val | UINT32_C(0xC0000000));
}

int64_t decode_packet_number(qslice_t *s) {
	// TODO use base correctly
	if (s->p == s->e) {
		return -1;
	}
	uint8_t *p = s->p++;
	uint8_t hdr = *p;
	switch (hdr >> 6) {
	default:
		return (hdr & 0x7F);
	case 2:
		if (s->p == s->e) {
			return -1;
		}
		return (((uint16_t)hdr & 0x3F) << 8) | *(s->p++);
	case 3:
		if (s->p + 3 > s->e) {
			return -1;
		}
		s->p += 3;
		return (big_32(p) & UINT32_C(0x3FFFFFFF));
	}
}

static int append_slice_16(qslice_t *s, qslice_t data) {
	size_t len = data.e - data.p;
	size_t have = s->e - s->p;
	if (len + 2 > have) {
		return -1;
	}
	s->p = write_big_16(s->p, (uint16_t)len);
	s->p = append(s->p, data.p, len);
	return 0;
}

static int decode_slice_16(qslice_t *s, qslice_t *data) {
	uint8_t *p = s->p + 2;
	if (p > s->e) {
		return -1;
	}
	uint8_t *e = p + big_16(s->p);
	if (e > s->e) {
		return -1;
	}
	s->p = e;
	data->p = p;
	data->e = e;
	return 0;
}

static int decode_slice_24(qslice_t *s, qslice_t *data) {
	uint8_t *p = s->p + 3;
	if (p > s->e) {
		return -1;
	}
	uint8_t *e = p + big_24(s->p);
	if (e > s->e) {
		return -1;
	}
	data->p = p;
	data->e = e;
	s->p = e;
	return 0;
}

int encode_server_hello(const qconnection_t *c, qslice_t *ps) {
	// check fixed size headers - up to and including extensions list size & tls version
	qslice_t s = *ps;
	if (s.p + 1 + 3 + 2 + QUIC_RANDOM_SIZE + 1 + 2 + 1 + 2 + 2 + 2 + 2 > s.e) {
		return -1;
	}

	// TLS header
	*(s.p++) = SERVER_HELLO;
	s.p += 3;
	uint8_t *record_begin = s.p;

	// legacy version
	s.p = write_big_16(s.p, TLS_LEGACY_VERSION);

	// random field
	s.p = append(s.p, c->server_random, QUIC_RANDOM_SIZE);

	// legacy session ID - not used in QUIC
	*(s.p++) = 0;

	// cipher
	s.p = write_big_16(s.p, c->cipher->cipher);

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
	if (c->key_num) {
		if (s.p + 2 + 2 + 2 + 2 + 1 + BR_EC_KBUF_PUB_MAX_SIZE > s.e) {
			return -1;
		}
		const br_ec_private_key *sk = &c->keys[0];
		s.p = write_big_16(s.p, KEY_SHARE);
		s.p += 2;
		uint8_t *ext_start = s.p;
		s.p = write_big_16(s.p, (uint16_t)sk->curve);
		s.p += 2;
		uint8_t *key_start = s.p;
		*(s.p++) = EC_KEY_UNCOMPRESSED;
		s.p += br_ec_compute_pub(br_ec_get_default(), NULL, s.p, sk);

		write_big_16(key_start - 2, (uint16_t)(s.p - key_start));
		write_big_16(ext_start - 2, (uint16_t)(s.p - ext_start));
	}

	write_big_16(list_start-2, (uint16_t)(s.p - list_start));
	write_big_24(record_begin - 3, (uint32_t)(s.p - record_begin));
	ps->p = s.p;
	return 0;
}

int encode_client_hello(const qconnection_t *c, qslice_t *ps) {
	// check fixed entries - up to and including cipher list size
	qslice_t s = *ps;
	if (s.p + 4 + 2 + QUIC_RANDOM_SIZE + 1 + 2 > s.e) {
		return -1;
	}

	// TLS record
	*(s.p++) = CLIENT_HELLO;
	s.p += 3;
	uint8_t *record_begin = s.p;

	// legacy version
	s.p = write_big_16(s.p, TLS_LEGACY_VERSION);

	// random field
	memcpy(s.p, c->client_random, QUIC_RANDOM_SIZE);
	s.p += QUIC_RANDOM_SIZE;

	// legacy session ID - not used in QUIC
	*(s.p++) = 0;

	// cipher suites
	s.p += 2;
	uint8_t *cipher_begin = s.p;
	for (size_t i = 0; c->params->ciphers[i] != NULL; i++) {
		if (s.p + 2 > s.e) {
			return -1;
		}
		s.p = write_big_16(s.p, c->params->ciphers[i]->cipher);
	}

	// compression methods
	if (s.p + 2 > s.e) {
		return -1;
	}
	*(s.p++) = 1;
	*(s.p++) = TLS_COMPRESSION_NULL;

	// extensions size in bytes - will fill out later
	if (s.p + 2 > s.e) {
		return -1;
	}
	s.p += 2;
	uint8_t *ext_start = s.p;

	// server name
	size_t name_len = strlen(c->server_name);
	if (name_len) {
		if (s.p + 2+2+2+1+2 + name_len > s.e) {
			return -1;
		}
		s.p = write_big_16(s.p, SERVER_NAME);
		s.p = write_big_16(s.p, (uint16_t)(2 + 1 + 2 + name_len));
		s.p = write_big_16(s.p, (uint16_t)(1 + 2 + name_len));
		*(s.p++) = HOST_NAME_TYPE;
		s.p = write_big_16(s.p, (uint16_t)name_len);
		s.p = append(s.p, c->server_name, name_len);
	}

	// supported groups
	size_t group_len = strlen(c->params->groups);
	if (s.p + 2 + 2 + 2 + group_len > s.e) {
		return -1;
	}
	s.p = write_big_16(s.p, SUPPORTED_GROUPS);
	s.p = write_big_16(s.p, (uint16_t)(2 + group_len));
	s.p = write_big_16(s.p, (uint16_t)(group_len));
	for (size_t i = 0; i < group_len; i++) {
		s.p = write_big_16(s.p, c->params->groups[i]);
	}

	// signature algorithms
	if (s.p + 6 > s.e) {
		return -1;
	}
	s.p = write_big_16(s.p, SIGNATURE_ALGORITHMS);
	s.p += 4;
	uint8_t *algo_start = s.p;
	for (size_t i = 0; c->params->signatures[i] != NULL; i++) {
		if (s.p + 2 > s.e) {
			return -1;
		}
		s.p = write_big_16(s.p, c->params->signatures[i]->algorithm);
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
	s.p = write_big_16(s.p, 0xFAFA); // grease
	s.p = write_big_16(s.p, TLS_VERSION);

	// key share
	if (c->key_num) {
		if (s.p + 6 > s.e) {
			return -1;
		}
		s.p = write_big_16(s.p, KEY_SHARE);
		s.p += 4; // fill out the header later once we know the length
		uint8_t *keys_start = s.p;
		for (size_t i = 0; i < c->key_num; i++) {
			if (s.p + 2 + 2 + 1 + BR_EC_KBUF_PUB_MAX_SIZE > s.e) {
				return -1;
			}
			const br_ec_private_key *sk = &c->keys[i];
			s.p = write_big_16(s.p, (uint16_t)sk->curve);
			s.p += 2;
			uint8_t *key_start = s.p;
			*(s.p++) = EC_KEY_UNCOMPRESSED;
			s.p += br_ec_compute_pub(br_ec_get_default(), NULL, s.p, sk);
			write_big_16(key_start - 2, (uint16_t)(s.p - key_start));
		}
		write_big_16(keys_start - 4, (uint16_t)(s.p - keys_start + 2));
		write_big_16(keys_start - 2, (uint16_t)(s.p - keys_start));
	}
	
	write_big_16(ext_start-2, (uint16_t)(s.p - ext_start));
	write_big_24(record_begin - 3, (uint32_t)(s.p - record_begin));
	ps->p = s.p;
	return 0;
}

int encode_certificates(qslice_t *ps, const qsigner_class *const *signer) {
	qslice_t s = *ps;
	if (s.p + 4 + 1 + 3 > s.e) {
		return -1;
	}

	// TLS record
	*(s.p++) = CERTIFICATE;
	s.p += 3;
	uint8_t *record_begin = s.p;

	// request context
	*(s.p++) = 0;

	// cert list
	s.p += 3;
	uint8_t *list_begin = s.p;

	const qcertificate_t *c = NULL;
	for (size_t i = 0;;i++) {
		const br_x509_certificate *c = (*signer)->get_cert(signer, i);
		if (!c) {
			break;
		} else if (s.p + 3 + c->data_len + 2 > s.e) {
			return -1;
		}
		s.p = write_big_24(s.p, (uint32_t)c->data_len);
		s.p = append(s.p, c->data, c->data_len);
		s.p = write_big_16(s.p, 0); // extensions
	}

	write_big_24(list_begin - 3, (uint32_t)(s.p - list_begin));
	write_big_24(record_begin - 3, (uint32_t)(s.p - record_begin));
	ps->p = s.p;
	return 0;
}

int encode_verify(qslice_t *ps, const qsignature_class *type, const uint8_t *sig, size_t len) {
	qslice_t s = *ps;
	if (s.p + 4 + 2 + 2 + len > s.e) {
		return -1;
	}

	// TLS record
	*(s.p++) = CERTIFICATE_VERIFY;
	s.p += 3;
	uint8_t *record_begin = s.p;

	// algorithm
	s.p = write_big_16(s.p, type->algorithm);

	// signature
	s.p = write_big_16(s.p, (uint16_t)len);
	s.p = append(s.p, sig, len);

	write_big_24(record_begin - 3, (uint32_t)(s.p - record_begin));
	ps->p = s.p;
	return 0;
}

int encode_finished(qslice_t *ps, const uint8_t *verify, size_t len) {
	qslice_t s = *ps;
	if (s.p + 4 + len > s.e) {
		return -1;
	}

	// TLS record
	*(s.p++) = FINISHED;
	s.p = write_big_24(s.p, (uint32_t)len);

	// verify data
	s.p = append(s.p, verify, len);
	ps->p = s.p;
	return 0;
}

int qc_decode_request(qconnect_request_t *h, void *buf, size_t len, tick_t rxtime, const qcrypto_params_t *params) {
	h->rxtime = rxtime;
	qslice_t s;
	s.p = (uint8_t*)buf;
	s.e = s.p + len;

	// check fixed size headers - up to and including cipher list size
	if (s.p + 2 + QUIC_RANDOM_SIZE + 1 + 2 > s.e) {
		return -1;
	}

	// legacy version
	if (big_16(s.p) != TLS_LEGACY_VERSION) {
		return -1;
	}
	s.p += 2;

	// random nonce
	h->random = s.p;
	s.p += QUIC_RANDOM_SIZE;

	// legacy session - not supported in QUIC
	if (*(s.p++) != 0) {
		return -1;
	}

	// ciphers
	qslice_t ciphers;
	if (decode_slice_16(&s, &ciphers) || ((ciphers.e - ciphers.p) & 1)) {
		return -1;
	}

	// only null compression allowed
	if (s.p + 2 > s.e || *(s.p++) != 1 || *(s.p++) != TLS_COMPRESSION_NULL) {
		return -1;
	}

	// switch to processing extensions
	if (decode_slice_16(&s, &s)) {
		return -1;
	}

	bool have_my_version = false;

	while (s.p < s.e) {
		if (s.p + 4 > s.e) {
			return -1;
		}
		uint16_t type = big_16(s.p);
		size_t ext_len = big_16(s.p + 2);
		qslice_t ext;
		ext.p = s.p + 4;
		ext.e = ext.p + ext_len;
		s.p = ext.e;
		switch (type) {
		case SERVER_NAME: {
			qslice_t names;
			if (decode_slice_16(&ext, &names)) {
				return -1;
			}
			while (names.p < names.e) {
				uint8_t name_type = *(names.p++);
				qslice_t other_name;
				if (decode_slice_16(&names, (name_type == HOST_NAME_TYPE) ? &h->server_name : &other_name)) {
					return -1;
				}
			}
			break;
		}
		case SUPPORTED_GROUPS:
			if (decode_slice_16(&ext, &h->groups) || ((h->groups.e - h->groups.p) & 1)) {
				return -1;
			}
			break;
		case SIGNATURE_ALGORITHMS:
			if (decode_slice_16(&ext, &h->algorithms) || ((h->algorithms.e - h->algorithms.p) & 1)) {
				return -1;
			}
			break;
		case SUPPORTED_VERSIONS: {
			if (ext.p == ext.e) {
				return -1;
			}
			uint8_t vlen = *(ext.p++);
			if (ext.p + vlen > ext.e || (vlen & 1)) {
				return -1;
			}
			for (size_t i = 0; i < vlen / 2; i++) {
				if (big_16(ext.p + (2 * i)) == TLS_VERSION) {
					have_my_version = true;
				}
			}
			break;
		}
		case KEY_SHARE: {
			qslice_t keys;
			if (decode_slice_16(&ext, &keys)) {
				return -1;
			}
			while (keys.p < keys.e && h->key_num < QUIC_MAX_KEYSHARE) {
				if (keys.p + 2 > keys.e) {
					return -1;
				}
				uint16_t group = big_16(keys.p);
				keys.p += 2;
				qslice_t key;
				if (decode_slice_16(&keys, &key)) {
					return -1;
				}
				if (key.p == key.e || key.p[0] != EC_KEY_UNCOMPRESSED) {
					continue;
				}
				br_ec_public_key *k = &h->keys[h->key_num++];
				k->curve = group;
				k->q = key.p + 1;
				k->qlen = key.e - k->q;
			}
			break;
		}
		}
	}

	if (!have_my_version) {
		return -1;
	}

	return 0;
}


struct crypto_run {
	unsigned off;
	unsigned have;
	uint8_t *base;
	uint8_t *p;
};

static void reset_decoder(struct crypto_decoder *d) {
	d->bufsz = 0;
	d->depth = 0;
	d->have_bytes = 0;
	d->end = UINT32_MAX;
}

static int getword(struct crypto_decoder *d, struct crypto_run *r, uint8_t need) {
	if (r->off + need > d->end) {
		return CRYPTO_ERROR;
	} else if (r->off + need > r->have) {
		unsigned sz = r->have - r->off;
		memcpy(&d->buf[d->bufsz], r->base + r->off, sz);
		d->bufsz += (uint8_t)sz;
		return CRYPTO_MORE;
	} else if (!d->bufsz) {
		r->p = r->base + r->off;
		r->off += need;
		return 1;
	} else {
		unsigned sz = need - d->bufsz;
		memcpy(&d->buf[d->bufsz], r->base + r->off, sz);
		r->off += sz;
		r->p = d->buf;
		d->bufsz = 0;
		return 1;
	}
}

static int getbytes(struct crypto_decoder *d, struct crypto_run *r, void *dst, size_t need) {
	unsigned have = d->have_bytes;
	need -= have;
	if (r->off + need > d->end) {
		return CRYPTO_ERROR;
	} else if (r->off + need > r->have) {
		unsigned sz = r->have - r->off;
		memcpy((char*)dst + have, r->base + r->off, sz);
		d->have_bytes += sz;
		return CRYPTO_MORE;
	} else {
		memcpy((char*)dst + have, r->base + r->off, need);
		r->off += (unsigned)need;
		d->have_bytes = 0;
		return 1;
	}
}

#define GET1 if (r.off == d->end) {return CRYPTO_ERROR;} else if (r.off == r.have) {return CRYPTO_MORE;} else {r.p = &r.base[r.off++];}
#define GET2 if ((err = getword(d,&r,2)) > 0) {} else return err
#define GET3 if ((err = getword(d,&r,3)) > 0) {} else return err
#define GET4 if ((err = getword(d,&r,4)) > 0) {} else return err
#define GETBYTES(P,SZ) if ((err = getbytes(d,&r,(P),(SZ))) > 0) {} else return err
#define GOTOEND if (r.have >= d->end) {r.off = d->end;} else return CRYPTO_MORE
#define STATE(ENUM) d->state = ENUM; case ENUM
#define PUSH_END d->stack[d->depth++] = d->end; d->end
#define POP_END d->stack[--d->depth]

enum server_hello_state {
	SHELLO_START,
	SHELLO_HEADER,
	SHELLO_LEGACY_VERSION,
	SHELLO_RANDOM,
	SHELLO_LEGACY_SESSION,
	SHELLO_CIPHER,
	SHELLO_COMPRESSION,
	SHELLO_EXT_LIST_SIZE,
	SHELLO_EXT_HEADER,
	SHELLO_SUPPORTED_VERSION,
	SHELLO_KEY_GROUP,
	SHELLO_KEY_SIZE,
	SHELLO_KEY_TYPE,
	SHELLO_KEY_DATA,
	SHELLO_FINISH_EXTENSION,
	SHELLO_FINISH,
};

int decode_server_hello(struct crypto_decoder *d, struct server_hello *s, unsigned off, const void *data, size_t size) {
	struct crypto_run r;
	r.off = off;
	r.have = off + (unsigned)size;
	r.base = (uint8_t*)data - off;

	int err;

	switch (d->state) {
	default:
		reset_decoder(d);
		s->tls_version = 0;
		s->key.curve = 0;
		s->key.qlen = 0;
	STATE(SHELLO_HEADER):
		GET4;
		if (r.p[0] != SERVER_HELLO) {
			return CRYPTO_ERROR;
		}
		d->end = r.off + big_24(r.p+1);
	STATE(SHELLO_LEGACY_VERSION):
		GET2;
		if (big_16(r.p) != TLS_LEGACY_VERSION) {
			return CRYPTO_ERROR;
		}
	STATE(SHELLO_RANDOM):
		GETBYTES(s->random, QUIC_RANDOM_SIZE);
	STATE(SHELLO_LEGACY_SESSION):
		GET1;
		if (*r.p) {
			// legacy sessions are not supported in QUIC
			return CRYPTO_ERROR;
		}
	STATE(SHELLO_CIPHER):
		GET2;
		s->cipher = big_16(r.p);
	STATE(SHELLO_COMPRESSION):
		GET1;
		if (*r.p != TLS_COMPRESSION_NULL) {
			// only null compression is supported in TLS 1.3
			return CRYPTO_ERROR;
		}
	STATE(SHELLO_EXT_LIST_SIZE):
		GET2;
		PUSH_END = r.off + big_16(r.p);
	start_extension:
		if (r.off == d->end) {
			d->end = POP_END;
			goto finish_record;
		}
	STATE(SHELLO_EXT_HEADER):
		GET4;
		PUSH_END = r.off + big_16(r.p + 2);
		switch (big_16(r.p)) {
		case KEY_SHARE:
			goto key_share;
		case SUPPORTED_VERSIONS:
			goto supported_version;
		default:
			goto finish_extension;
		}
	finish_extension:
	STATE(SHELLO_FINISH_EXTENSION) :
		GOTOEND;
		d->end = POP_END;
		goto start_extension;


	supported_version:
	STATE(SHELLO_SUPPORTED_VERSION):
		GET2;
		s->tls_version = big_16(r.p);
		goto finish_extension;



	key_share:
	STATE(SHELLO_KEY_GROUP):
		GET2;
		s->key.curve = big_16(r.p);
	STATE(SHELLO_KEY_SIZE):
		GET2;
		s->key.qlen = big_16(r.p);
		if (!s->key.qlen) {
			// first byte is the key type
			return CRYPTO_ERROR;
		}
		s->key.qlen--;
	STATE(SHELLO_KEY_TYPE):
		GET1;
		if (*r.p != EC_KEY_UNCOMPRESSED) {
			return CRYPTO_ERROR;
		}
	STATE(SHELLO_KEY_DATA):
		GETBYTES(s->key_data, (uint32_t)s->key.qlen);
		s->key.q = s->key_data;
		goto finish_extension;



	finish_record:
	STATE(SHELLO_FINISH):
		GOTOEND;
	    assert(!d->depth);
		return (int)(r.off - off);
	}
}

enum cert_state {
	CERTIFICATES_START,
	CERTIFICATES_HEADER,
	CERTIFICATES_CONTEXT,
	CERTIFICATES_LIST_SIZE,
	CERTIFICATES_DATA_SIZE,
	CERTIFICATES_DATA,
	CERTIFICATES_EXT_SIZE,
	CERTIFICATES_EXT,
	CERTIFICATES_FINISH,
};


int decode_certificates(struct crypto_decoder *d, const br_x509_class **x, unsigned off, const void *data, size_t size) {
	struct crypto_run r;
	r.off = off;
	r.have = (unsigned)(off + size);
	r.base = (uint8_t*)data - off;

	int err;

	switch (d->state) {
	default:
		reset_decoder(d);
	STATE(CERTIFICATES_HEADER):
		GET4;
		if (r.p[0] != CERTIFICATE) {
			return CRYPTO_ERROR;
		}
		d->end = r.off + big_24(r.p+1);
	STATE(CERTIFICATES_CONTEXT):
		GET1;
		if (*r.p != 0) {
			// QUIC does not support post handshake auth
			// client auth during the handshake must not use the request context
			return CRYPTO_ERROR;
		}
	STATE(CERTIFICATES_LIST_SIZE):
		GET3;
		PUSH_END = r.off + big_24(r.p);
	next_certificate:
		if (r.off == d->end) {
			d->end = POP_END;
			goto finish_record;
		}
	STATE(CERTIFICATES_DATA_SIZE):
		GET3;
		PUSH_END = r.off + big_24(r.p);
		(*x)->start_cert(x, big_24(r.p));
	STATE(CERTIFICATES_DATA):
		if (r.have < d->end) {
			(*x)->append(x, r.base + r.off, r.have - r.off);
			return CRYPTO_MORE;
		}
		(*x)->append(x, r.base + r.off, d->end - r.off);
		r.off = d->end;
		d->end = POP_END;
		(*x)->end_cert(x);
	STATE(CERTIFICATES_EXT_SIZE):
		GET2;
		PUSH_END = r.off + big_16(r.p);
	STATE(CERTIFICATES_EXT):
		// we don't support any extensions currently, so just skip over the data
		GOTOEND;
	    d->end = POP_END;
		goto next_certificate;

	finish_record:
	STATE(CERTIFICATES_FINISH) :
		GOTOEND;
	    assert(!d->depth);
	    return (int)(r.off - off);
	}
}

enum verify_state {
	VERIFY_START,
	VERIFY_HEADER,
	VERIFY_ALGORITHM,
	VERIFY_SIG_SIZE,
	VERIFY_SIG_DATA,
	VERIFY_FINISH,
};

int decode_verify(struct crypto_decoder *d, struct verify *v, unsigned off, const void *data, size_t size) {
	struct crypto_run r;
	r.off = off;
	r.have = off + (unsigned)size;
	r.base = (uint8_t*)data - off;

	int err;
	switch (d->state) {
	default:
		reset_decoder(d);
	STATE(VERIFY_HEADER):
		GET4;
		if (r.p[0] != CERTIFICATE_VERIFY) {
			return CRYPTO_ERROR;
		}
		d->end = r.off + big_24(r.p+1);
	STATE(VERIFY_ALGORITHM):
		GET2;
		v->algorithm = big_16(r.p);
	STATE(VERIFY_SIG_SIZE):
		GET2;
		v->sig_size = big_16(r.p);
		if (v->sig_size > sizeof(v->signature)) {
			return CRYPTO_ERROR;
		}
	STATE(VERIFY_SIG_DATA):
		GETBYTES(v->signature, v->sig_size);
	STATE(VERIFY_FINISH):
		GOTOEND;
		return (int)(r.off - off);
	}
}

enum finished_state {
	FINISHED_START,
	FINISHED_HEADER,
	FINISHED_DATA,
};

int decode_finished(struct crypto_decoder *d, struct finished *f, unsigned off, const void *data, size_t size) {
	struct crypto_run r;
	r.off = off;
	r.have = off + (unsigned)size;
	r.base = (uint8_t*)data - off;

	int err;
	switch (d->state) {
	default:
		reset_decoder(d);
	STATE(FINISHED_HEADER) :
		GET4;
		if (r.p[0] != FINISHED) {
			return CRYPTO_ERROR;
		}
		f->size = big_24(r.p+1);
		d->end = r.off + f->size;
		if (f->size > QUIC_MAX_HASH_SIZE) {
			return CRYPTO_ERROR;
		}
	STATE(FINISHED_DATA) :
		GETBYTES(f->verify, f->size);
		return (int)(r.off - off);
	}
}

