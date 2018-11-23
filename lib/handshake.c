#include "handshake.h"
#include "connection.h"
#include "kdf.h"


// TLS records
#define TLS_RECORD_HEADER_SIZE 4
#define CLIENT_HELLO 1
#define SERVER_HELLO 2
#define NEW_SESSION_TICKET 4
#define END_OF_EARLY_DATA 5
#define ENCRYPTED_EXTENSIONS 8
#define CERTIFICATE 11
#define CERTIFICATE_REQUEST 13
#define CERTIFICATE_VERIFY 15
#define FINISHED 20
#define KEY_UPDATE 24
#define MESSAGE_HASH 254

#define TLS_LEGACY_VERSION 0x303

#define EC_KEY_UNCOMPRESSED 4

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
#define QUIC_TRANSPORT_PARAMETERS 0xFFA5

#define TP_stream_data_bidi_local 0x00
#define TP_stream_data_bidi_remote 0x0A
#define TP_stream_data_uni 0x0B
#define TP_max_data 0x01
#define TP_bidi_streams 0x02
#define TP_uni_streams 0x08

// server name
#define HOST_NAME_TYPE 0

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

int decode_varint(qslice_t *s, uint64_t *pval) {
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

size_t packet_number_length(uint64_t val) {
	return 4;
}

uint8_t *encode_packet_number(uint8_t *p, uint64_t val) {
	// TODO use base correctly
	return write_big_32(p, (uint32_t)val | UINT32_C(0xC0000000));
}

int decode_packet_number(qslice_t *s, uint64_t *pval) {
	// TODO use base correctly
	if (s->p == s->e) {
		return -1;
	}
	uint8_t *p = s->p++;
	uint8_t hdr = *p;
	switch (hdr >> 6) {
	default:
		*pval = (hdr & 0x7F);
		return 0;
	case 2:
		if (s->p == s->e) {
			return -1;
		}
		*pval = (((uint16_t)hdr & 0x3F) << 8) | *(s->p++);
		return 0;
	case 3:
		if (s->p + 3 > s->e) {
			return -1;
		}
		s->p += 3;
		*pval = (big_32(p) & UINT32_C(0x3FFFFFFF));
		return 0;
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
	}
	return 0;
}


static int encode_transport_params(qslice_t *s, const qconnect_params_t *p) {
	if (s->p + 2 > s->e) {
		return -1;
	}
	s->p += 2;
	uint8_t *params_start = s->p;
	if (p->stream_data_bidi_local && encode_transport(s, TP_stream_data_bidi_local, p->stream_data_bidi_local, 4)) {
		return -1;
	}
	if (p->stream_data_bidi_remote && encode_transport(s, TP_stream_data_bidi_remote, p->stream_data_bidi_remote, 4)) {
		return -1;
	}
	if (p->stream_data_uni && encode_transport(s, TP_stream_data_uni, p->stream_data_uni, 4)) {
		return -1;
	}
	if (p->bidi_streams && encode_transport(s, TP_bidi_streams, p->bidi_streams - 1, 2)) {
		return -1;
	}
	if (p->uni_streams && encode_transport(s, TP_uni_streams, p->uni_streams - 1, 2)) {
		return -1;
	}
	if (p->max_data && encode_transport(s, TP_max_data, p->max_data, 4)) {
		return -1;
	}
	write_big_16(params_start - 2, (uint16_t)(s->p - params_start));
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

int encode_encrypted_extensions(const qconnection_t *c, qslice_t *ps) {
	const qconnect_params_t *p = c->params;

	// check fixed size headers - up to and including extensions list size & tls version
	qslice_t s = *ps;
	if (s.p + 1 + 3 + 2 > s.e) {
		return -1;
	}

	// TLS header
	*(s.p++) = ENCRYPTED_EXTENSIONS;
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
	s.p = write_big_32(s.p, QUIC_VERSION);
	// supported versions
	*(s.p++) = 4;
	s.p = write_big_32(s.p, QUIC_VERSION);
	if (encode_transport_params(&s, p)) {
		return -1;
	}
	write_big_16(transport_start - 2, (uint16_t)(s.p - transport_start));

	write_big_16(list_start - 2, (uint16_t)(s.p - list_start));
	write_big_24(record_begin - 3, (uint32_t)(s.p - record_begin));
	ps->p = s.p;
	return 0;
}

int encode_client_hello(const qconnection_t *c, qslice_t *ps) {
	const qconnect_params_t *p = c->params;

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
	for (size_t i = 0; p->ciphers[i] != NULL; i++) {
		if (s.p + 2 > s.e) {
			return -1;
		}
		s.p = write_big_16(s.p, p->ciphers[i]->cipher);
	}
	write_big_16(cipher_begin - 2, (uint16_t)(s.p - cipher_begin));

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
	size_t group_len = strlen(p->groups);
	if (s.p + 2 + 2 + 2 + 2*group_len > s.e) {
		return -1;
	}
	s.p = write_big_16(s.p, SUPPORTED_GROUPS);
	s.p = write_big_16(s.p, (uint16_t)(2 + 2*group_len));
	s.p = write_big_16(s.p, (uint16_t)(2*group_len));
	for (size_t i = 0; i < group_len; i++) {
		s.p = write_big_16(s.p, p->groups[i]);
	}

	// signature algorithms
	if (s.p + 6 > s.e) {
		return -1;
	}
	s.p = write_big_16(s.p, SIGNATURE_ALGORITHMS);
	s.p += 4;
	uint8_t *algo_start = s.p;
	for (size_t i = 0; p->signatures[i] != NULL; i++) {
		if (s.p + 2 > s.e) {
			return -1;
		}
		s.p = write_big_16(s.p, p->signatures[i]->algorithm);
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

	// transport params
	if (s.p + 2 + 2 + 2 > s.e) {
		return -1;
	}
	s.p = write_big_16(s.p, QUIC_TRANSPORT_PARAMETERS);
	s.p += 2;
	uint8_t *transport_start = s.p;
	s.p = write_big_32(s.p, QUIC_VERSION);
	if (encode_transport_params(&s, p)) {
		return -1;
	}
	write_big_16(transport_start - 2, (uint16_t)(s.p - transport_start));
	
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

int decode_client_hello(qslice_t *ps, qconnect_request_t *h, const qconnect_params_t *params) {
	// check fixed size headers - up to and including cipher list size
	qslice_t s = *ps;
	if (s.p + 1 + 3 + 2 + QUIC_RANDOM_SIZE + 1 + 2 > s.e) {
		return -1;
	}

	// TLS record header
	if (*(s.p++) != CLIENT_HELLO) {
		return -1;
	}
	size_t len = big_24(s.p);
	s.p += 3;
	if (s.p + len > s.e) {
		return -1;
	}
	ps->p = s.p + len;
	s.e = ps->p;

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
	while (ciphers.p < ciphers.e && !h->cipher) {
		uint16_t code = big_16(ciphers.p);
		ciphers.p += 2;
		h->cipher = find_cipher(params->ciphers, code);
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
		uint16_t ext_type = big_16(s.p);
		size_t ext_len = big_16(s.p + 2);
		qslice_t ext;
		ext.p = s.p + 4;
		ext.e = ext.p + ext_len;
		s.p = ext.e;

		switch (ext_type) {
		case SERVER_NAME: {
			qslice_t names;
			if (decode_slice_16(&ext, &names)) {
				return -1;
			}
			while (names.p < names.e) {
				uint8_t name_type = *(names.p++);
				qslice_t name;
				if (decode_slice_16(&names, &name)) {
					return -1;
				}
				if (name_type == HOST_NAME_TYPE) {
					h->server_name = (char*)name.p;
					h->name_len = (size_t)(name.e - name.p);
					break;
				}
			}
			break;
		}
		case SUPPORTED_GROUPS: {
			qslice_t g;
			if (decode_slice_16(&ext, &g) || ((g.e - g.p) & 1)) {
				return -1;
			}
			if (!h->key.curve) {
				while (g.p < g.e) {
					uint16_t group = big_16(g.p);
					g.p += 2;
					if (group < 128 && strchr(params->groups, (char)group)) {
						h->key.curve = group;
						break;
					}
				}
			}
			break;
		}
		case SIGNATURE_ALGORITHMS: {
			qslice_t a;
			if (decode_slice_16(&ext, &a) || ((a.e - a.p) & 1)) {
				return -1;
			}
			while (a.p < a.e) {
				uint16_t algo = big_16(a.p);
				a.p += 2;
				const qsignature_class *type = find_signature(params->signatures, algo);
				if (type && type->curve < 64) {
					h->signatures |= UINT64_C(1) << type->curve;
				}
			}
			break;
		}
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
			while (keys.p + 2 < keys.e) {
				uint16_t group = big_16(keys.p);
				keys.p += 2;
				qslice_t k;
				if (decode_slice_16(&keys, &k)) {
					return -1;
				}
				if (group < 128 && strchr(params->groups, (char)group) && k.p < k.e && k.p[0] == EC_KEY_UNCOMPRESSED) {
					h->key.curve = group;
					h->key.q = k.p + 1;
					h->key.qlen = k.e - h->key.q;
					break;
				}
			}
			break;
		}
		case QUIC_TRANSPORT_PARAMETERS: {
			if (ext.p + 4 > ext.e) {
				return -1;
			}
			ext.p += 4; // initial version
			qslice_t p;
			if (decode_slice_16(&ext, &p)) {
				return -1;
			}
			while (p.p +2 < p.e) {
				uint16_t key = big_16(p.p);
				p.p += 2;
				qslice_t value;
				if (decode_slice_16(&p, &value)) {
					return -1;
				}
				switch (key) {
				case TP_stream_data_bidi_local:
					if (value.e - value.p >= 4) {
						h->client_params.stream_data_bidi_local = big_32(value.p);
					}
					break;
				case TP_stream_data_bidi_remote:
					if (value.e - value.p >= 4) {
						h->client_params.stream_data_bidi_remote = big_32(value.p);
					}
					break;
				case TP_stream_data_uni:
					if (value.e - value.p >= 4) {
						h->client_params.stream_data_uni = big_32(value.p);
					}
					break;
				case TP_max_data:
					if (value.e - value.p >= 4) {
						h->client_params.max_data = big_32(value.p);
					}
					break;
				case TP_bidi_streams:
					if (value.e - value.p >= 2) {
						h->client_params.bidi_streams = (uint64_t)big_16(value.p) + 1;
					}
					break;
				case TP_uni_streams:
					if (value.e - value.p >= 2) {
						h->client_params.uni_streams = (uint64_t)big_16(value.p) + 1;
					}
					break;
				}
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

const br_hash_class **init_cipher(qconnection_t *c, const qcipher_class *cipher) {
	c->cipher = cipher;
	if (!cipher) {
		c->msg_hash = NULL;
	} else if (cipher->hash == &br_sha256_vtable) {
		c->msg_hash = &c->msg_sha256.vtable;
	} else if (cipher->hash == &br_sha384_vtable) {
		c->msg_hash = &c->msg_sha384.vtable;
	} else {
		c->msg_hash = NULL;
	}
	return c->msg_hash;
}

static const br_ec_private_key *find_private_key(qconnection_t *c, int curve) {
	for (size_t i = 0; i < c->key_num; i++) {
		if (c->keys[i].curve == curve) {
			return &c->keys[i];
		}
	}
	return NULL;
}

static int set_server_key(qconnection_t *c, const br_ec_public_key *pk, const uint8_t *msg_hash) {
	assert(c->is_client);
	const br_ec_private_key *sk = find_private_key(c, pk->curve);
	if (!sk) {
		return -1;
	}

	qpacket_buffer_t *hs = &c->pkts[QC_HANDSHAKE];
	if (generate_handshake_secrets(c->cipher, msg_hash, pk, sk, &hs->tkey, &hs->rkey, c->master_secret)) {
		return -1;
	}
	log_handshake(&hs->tkey, &hs->rkey, c->client_random, c->keylog);
	return 0;
}

static int check_signature(qconnection_t *c, uint16_t algorithm, const void *sig, size_t slen, const uint8_t *msg_hash) {
	const qsignature_class *type = find_signature(c->params->signatures, algorithm);
	if (!type) {
		return CRYPTO_ERROR;
	}

	uint8_t verify[QUIC_MAX_CERT_VERIFY_SIZE];
	size_t vlen = generate_cert_verify(*c->msg_hash, !c->is_client, msg_hash, verify);
	const br_x509_pkey *pk = (*c->validator)->get_pkey(c->validator, NULL);
	return type->verify(type, pk, verify, vlen, sig, slen);
}

static int check_finish(qconnection_t *c, const void *fin, size_t flen, const uint8_t *msg_hash) {
	qpacket_buffer_t *hs = &c->pkts[QC_HANDSHAKE];
	uint8_t verify[QUIC_MAX_HASH_SIZE];
	size_t vlen = generate_finish_verify(&hs->rkey, msg_hash, verify);
	if (vlen != flen || memcmp(fin, verify, vlen)) {
		return CRYPTO_ERROR;
	}
	return 0;
}


struct crypto_run {
	unsigned off;
	unsigned have;
	unsigned start;
	const uint8_t *base;
	const uint8_t *p;
};

static int getword(struct crypto_decoder *d, struct crypto_run *r, uint8_t need) {
	if (r->off + need > d->end) {
		return CRYPTO_ERROR;
	} else if (r->off + need > r->have) {
		unsigned sz = r->have - r->off;
		memcpy(&d->buf[d->bufsz], r->base + r->off, sz);
		d->bufsz += (uint8_t)sz;
		return 1;
	} else if (!d->bufsz) {
		r->p = r->base + r->off;
		r->off += need;
		return 0;
	} else {
		unsigned sz = need - d->bufsz;
		memcpy(&d->buf[d->bufsz], r->base + r->off, sz);
		r->off += sz;
		r->p = d->buf;
		d->bufsz = 0;
		return 0;
	}
}

static int getbytes(struct crypto_decoder *d, struct crypto_run *r, void *dst, size_t need) {
	uint32_t have = d->have_bytes;
	need -= have;
	if (r->off + need > d->end) {
		return CRYPTO_ERROR;
	} else if (r->off + need > r->have) {
		unsigned sz = r->have - r->off;
		memcpy((char*)dst + have, r->base + r->off, sz);
		d->have_bytes += sz;
		return 1;
	} else {
		memcpy((char*)dst + have, r->base + r->off, need);
		r->off += (unsigned)need;
		d->have_bytes = 0;
		return 0;
	}
}

static void update_msg_hash(const br_hash_class **h, struct crypto_run *r, uint8_t *hash) {
	(*h)->update(h, r->base + r->start, r->off - r->start);
	(*h)->out(h, hash);
	r->start = r->off;
}

#define PUSH_END d->stack[d->depth++] = d->end; d->end
#define POP_END d->stack[--d->depth]

#define GET_1(STATE) case STATE: if (r.off == d->end) {return CRYPTO_ERROR;} else if (r.off == r.have) {d->state = STATE; goto end;} else r.p = &r.base[r.off++]
#define GET_2(STATE) case STATE: if ((err = getword(d,&r,2)) != 0) {d->state = STATE; goto end;} else do{}while(0)
#define GET_3(STATE) case STATE: if ((err = getword(d,&r,3)) != 0) {d->state = STATE; goto end;} else do{}while(0)
#define GET_4(STATE) case STATE: if ((err = getword(d,&r,4)) != 0) {d->state = STATE; goto end;} else do{}while(0)
#define GOTO_END(STATE) case STATE: if (r.have < d->end) {d->state = STATE; goto end;} else r.off = d->end
#define GOTO_LEVEL(LEVEL,STATE) if (level != (LEVEL)) {d->state = STATE; d->next = 0; d->level = (LEVEL); goto end;} case STATE: do{}while(0)
#define GET_BYTES(P,SZ,STATE) d->state = STATE; case STATE: if ((err = getbytes(d,&r,(P),(SZ))) != 0) {d->state = STATE; goto end;} else do{}while(0)

enum decoder_state {
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

	EXTENSIONS_LEVEL,
	EXTENSIONS_HEADER,
	EXTENSIONS_LIST_SIZE,
	EXTENSIONS_EXT_HEADER,
	EXTENSIONS_FINISH_EXTENSION,
	EXTENSIONS_FINISH,
	EXTENSIONS_SUPPORTED_VERSIONS,
	EXTENSIONS_SUPPORTED_VERSIONS_SIZE,
	EXTENSIONS_NEGOTIATED_VERSION,
	EXTENSIONS_TP_LIST_SIZE,
	EXTENSIONS_TP_KEY,
	EXTENSIONS_TP_FINISH,
	EXTENSIONS_TP_stream_data_bidi_local,
	EXTENSIONS_TP_stream_data_bidi_remote,
	EXTENSIONS_TP_stream_data_uni,
	EXTENSIONS_TP_bidi_streams,
	EXTENSIONS_TP_uni_streams,
	EXTENSIONS_TP_max_data,

	CERTIFICATES_HEADER,
	CERTIFICATES_CONTEXT,
	CERTIFICATES_LIST_SIZE,
	CERTIFICATES_DATA_SIZE,
	CERTIFICATES_DATA,
	CERTIFICATES_EXT_SIZE,
	CERTIFICATES_EXT,
	CERTIFICATES_FINISH,

	VERIFY_START,
	VERIFY_HEADER,
	VERIFY_ALGORITHM,
	VERIFY_SIG_SIZE,
	VERIFY_SIG_DATA,
	VERIFY_FINISH,

	FINISHED_START,
	FINISHED_HEADER,
	FINISHED_DATA,
	FINISHED_LEVEL,

	TICKET_HEADER,
	TICKET_DATA,
};

void init_client_decoder(qconnection_t *c) {
	struct crypto_decoder *d = &c->rx_crypto;
	d->level = QC_INITIAL;
	d->next = 0;
	d->state = SHELLO_START;
	d->depth = 0;
	d->have_bytes = 0;
	d->bufsz = 0;
}

void init_server_decoder(qconnection_t *c) {
	struct crypto_decoder *d = &c->rx_crypto;
	d->level = QC_PROTECTED;
	d->next = 0;
	d->state = FINISHED_START;
	d->depth = 0;
	d->have_bytes = 0;
	d->bufsz = 0;
}

// Besides the client hello, all other crypto packets are decoded by using the a resumable decoder
// This makes it a bit more complex, but means we don't have to buffer packet data.
int decode_crypto(qconnection_t *c, enum qcrypto_level level, qslice_t *fd) {
	struct crypto_decoder *d = &c->rx_crypto;
	uint64_t off, len;
	if (decode_varint(fd, &off) || decode_varint(fd, &len) || len > (uint64_t)(fd->e - fd->p)) {
		return CRYPTO_ERROR;
	}
	const uint8_t *data = fd->p;
	fd->p += (size_t)len;

	if (level != d->level || off + len < (uint64_t)d->next) {
		// retransmit of old data
		return 0;
	} else if (off <= (uint64_t)d->next && off + len < UINT32_MAX) {
		size_t shift = (size_t)(d->next - off);
		data += shift;
		len -= shift;
		off += shift;
	} else {
		// out of order data
		return QC_ERR_DROP;
	}

	struct crypto_run r;
	r.off = (uint32_t)off;
	r.start = r.off;
	r.have = r.off + (uint32_t)len;
	r.base = data - r.off;

	d->next = r.have;

	int err = 0;

	switch (d->state) {

		// SERVER_HELLO

	case SHELLO_START:
		assert(!d->depth);
		d->end = UINT32_MAX;
		d->u.sh.tls_version = 0;
		d->u.sh.k.curve = 0;
		d->u.sh.k.qlen = 0;
		GET_4(SHELLO_HEADER);
		if (r.p[0] != SERVER_HELLO) {
			return CRYPTO_ERROR;
		}
		d->end = r.off + big_24(r.p+1);
		GET_2(SHELLO_LEGACY_VERSION);
		if (big_16(r.p) != TLS_LEGACY_VERSION) {
			return CRYPTO_ERROR;
		}
		GET_BYTES(c->server_random, QUIC_RANDOM_SIZE, SHELLO_RANDOM);
		GET_1(SHELLO_LEGACY_SESSION);
		if (*r.p) {
			// legacy sessions are not supported in QUIC
			return CRYPTO_ERROR;
		}
		GET_2(SHELLO_CIPHER);
		if (init_cipher(c, find_cipher(c->params->ciphers, big_16(r.p))) == NULL) {
			return CRYPTO_ERROR;
		}
		GET_1(SHELLO_COMPRESSION);
		if (*r.p != TLS_COMPRESSION_NULL) {
			// only null compression is supported in TLS 1.3
			return CRYPTO_ERROR;
		}
		GET_2(SHELLO_EXT_LIST_SIZE);
		PUSH_END = r.off + big_16(r.p);
	next_shello_extension:
 		if (r.off == d->end) {
			d->end = POP_END;
			goto finish_shello_record;
		}
		GET_4(SHELLO_EXT_HEADER);
		PUSH_END = r.off + big_16(r.p + 2);
		switch (big_16(r.p)) {
		case KEY_SHARE:
			goto key_share;
		case SUPPORTED_VERSIONS:
			goto supported_version;
		default:
			goto finish_shello_extension;
		}
	finish_shello_extension:
		GOTO_END(SHELLO_FINISH_EXTENSION);
		d->end = POP_END;
		goto next_shello_extension;
	finish_shello_record:
		if (d->u.sh.tls_version != TLS_VERSION) {
			return CRYPTO_ERROR;
		}
		GOTO_END(SHELLO_FINISH);
		update_msg_hash(c->msg_hash, &r, d->u.sh.msg_hash);
		if (set_server_key(c, &d->u.sh.k, d->u.sh.msg_hash)) {
			return CRYPTO_ERROR;
		}
		goto start_encrypted_extensions;

	supported_version:
		GET_2(SHELLO_SUPPORTED_VERSION);
		d->u.sh.tls_version = big_16(r.p);
		goto finish_shello_extension;

	key_share:
		GET_2(SHELLO_KEY_GROUP);
		d->u.sh.k.curve = big_16(r.p);
		GET_2(SHELLO_KEY_SIZE);
		d->u.sh.k.qlen = big_16(r.p);
		if (!d->u.sh.k.qlen) {
			// first byte is the key type
			return CRYPTO_ERROR;
		}
		d->u.sh.k.qlen--;
		GET_1(SHELLO_KEY_TYPE);
		if (*r.p != EC_KEY_UNCOMPRESSED) {
			return CRYPTO_ERROR;
		}
		GET_BYTES(d->u.sh.key_data, d->u.sh.k.qlen, SHELLO_KEY_DATA);
		d->u.sh.k.q = d->u.sh.key_data;
		goto finish_shello_extension;


		// ENCRYPTED_EXTENSIONS

	start_encrypted_extensions:
		c->pending_streams[0].max = 0;
		c->pending_streams[1].max = 0;
		memset(&c->max_stream_data, 0, sizeof(c->max_stream_data));
		c->max_data = 0;
		assert(!d->depth);
		d->end = UINT32_MAX;
		GOTO_LEVEL(QC_HANDSHAKE, EXTENSIONS_LEVEL);
		GET_4(EXTENSIONS_HEADER);
		if (r.p[0] != ENCRYPTED_EXTENSIONS) {
			return CRYPTO_ERROR;
		}
		d->end = r.off + big_24(r.p + 1);
		GET_2(EXTENSIONS_LIST_SIZE);
		PUSH_END = r.off + big_16(r.p);
	next_encrypted_extension:
		if (r.off == d->end) {
			d->end = POP_END;
			goto finish_encrypted_extensions;
		}
		GET_4(EXTENSIONS_EXT_HEADER);
		PUSH_END = r.off + big_16(r.p + 2);
		switch (big_16(r.p)) {
		case QUIC_TRANSPORT_PARAMETERS:
			goto transport_parameters;
		default:
			goto finish_encrypted_extension;
		}
	finish_encrypted_extension:
		GOTO_END(EXTENSIONS_FINISH_EXTENSION);
		d->end = POP_END;
		goto next_encrypted_extension;
	finish_encrypted_extensions:
		GOTO_END(EXTENSIONS_FINISH);
		goto start_certificates;

	transport_parameters:
		// ignore negotiated & supported versions
		GET_4(EXTENSIONS_NEGOTIATED_VERSION);
		GET_1(EXTENSIONS_SUPPORTED_VERSIONS_SIZE);
		PUSH_END = r.off + r.p[0];
		GOTO_END(EXTENSIONS_SUPPORTED_VERSIONS);
		d->end = POP_END;

		GET_2(EXTENSIONS_TP_LIST_SIZE);
		PUSH_END = r.off + big_16(r.p);
	next_tp:
		if (r.off == d->end) {
			d->end = POP_END;
			goto finish_encrypted_extension;
		}
		GET_4(EXTENSIONS_TP_KEY);
		PUSH_END = r.off + big_16(r.p + 2);
		switch (big_16(r.p)) {
		case TP_stream_data_bidi_local:
			goto stream_data_bidi_local;
		case TP_stream_data_bidi_remote:
			goto stream_data_bidi_remote;
		case TP_stream_data_uni:
			goto stream_data_uni;
		case TP_max_data:
			goto max_data;
		case TP_bidi_streams:
			goto bidi_streams;
		case TP_uni_streams:
			goto uni_streams;
		default:
			goto finish_tp;
		}
	finish_tp:
		GOTO_END(EXTENSIONS_TP_FINISH);
		d->end = POP_END;
		goto next_tp;
	stream_data_bidi_local:
		GET_4(EXTENSIONS_TP_stream_data_bidi_local);
		c->max_stream_data[STREAM_SERVER | STREAM_BIDI] = big_32(r.p);
		goto finish_tp;
	stream_data_bidi_remote:
		GET_4(EXTENSIONS_TP_stream_data_bidi_remote);
		c->max_stream_data[STREAM_CLIENT | STREAM_BIDI] = big_32(r.p);
		goto finish_tp;
	stream_data_uni:
		GET_4(EXTENSIONS_TP_stream_data_uni);
		c->max_stream_data[STREAM_CLIENT | STREAM_UNI] = big_32(r.p);
		goto finish_tp;
	bidi_streams:
		GET_2(EXTENSIONS_TP_bidi_streams);
		c->pending_streams[PENDING_BIDI].max = (uint64_t)big_16(r.p) + 1;
		goto finish_tp;
	uni_streams:
		GET_2(EXTENSIONS_TP_uni_streams);
		c->pending_streams[PENDING_UNI].max = (uint64_t)big_16(r.p) + 1;
		goto finish_tp;
	max_data:
		GET_4(EXTENSIONS_TP_max_data);
		c->max_data = big_32(r.p);
		goto finish_tp;


		// CERTIFICATE

	start_certificates:
		assert(!d->depth);
		d->end = UINT32_MAX;
		(*c->validator)->start_chain(c->validator, c->server_name);
		GET_4(CERTIFICATES_HEADER);
		if (r.p[0] != CERTIFICATE) {
			return CRYPTO_ERROR;
		}
		d->end = r.off + big_24(r.p + 1);
		GET_1(CERTIFICATES_CONTEXT);
		if (*r.p != 0) {
			// QUIC does not support post handshake authentication
			// client authentication during the handshake must not use the request context
			return CRYPTO_ERROR;
		}
		GET_3(CERTIFICATES_LIST_SIZE);
		PUSH_END = r.off + big_24(r.p);
	next_certificate:
		if (r.off == d->end) {
			d->end = POP_END;
			goto finish_certificates;
		}
		GET_3(CERTIFICATES_DATA_SIZE);
		PUSH_END = r.off + big_24(r.p);
		(*c->validator)->start_cert(c->validator, big_24(r.p));
		d->state = CERTIFICATES_DATA;
	case CERTIFICATES_DATA:
		if (r.have < d->end) {
			(*c->validator)->append(c->validator, r.base + r.off, r.have - r.off);
			goto end;
		}
		(*c->validator)->append(c->validator, r.base + r.off, d->end - r.off);
		r.off = d->end;
		d->end = POP_END;
		(*c->validator)->end_cert(c->validator);
		// we don't support any extensions currently, so just skip over the data
		GET_2(CERTIFICATES_EXT_SIZE);
		PUSH_END = r.off + big_16(r.p);
		GOTO_END(CERTIFICATES_EXT);
		d->end = POP_END;
		goto next_certificate;
	finish_certificates:
		GOTO_END(CERTIFICATES_FINISH);
		err = (*c->validator)->end_chain(c->validator);
		if (err) {
			return err;
		}
		goto start_verify;


		// CERTIFICATE_VERIFY

	start_verify:
		update_msg_hash(c->msg_hash, &r, d->u.v.msg_hash);
		assert(!d->depth);
		d->end = UINT32_MAX;
		GET_4(VERIFY_HEADER);
		if (r.p[0] != CERTIFICATE_VERIFY) {
			return CRYPTO_ERROR;
		}
		d->end = r.off + big_24(r.p + 1);
		GET_2(VERIFY_ALGORITHM);
		d->u.v.algorithm = big_16(r.p);
		GET_2(VERIFY_SIG_SIZE);
		d->u.v.len = big_16(r.p);
		if (d->u.v.len > sizeof(d->u.v.sig)) {
			return CRYPTO_ERROR;
		}
		GET_BYTES(d->u.v.sig, d->u.v.len, VERIFY_SIG_DATA);
		GOTO_END(VERIFY_FINISH);
		err = check_signature(c, d->u.v.algorithm, d->u.v.sig, d->u.v.len, d->u.v.msg_hash);
		if (err) {
			return err;
		}
		goto start_finish;


		// FINISH

	start_finish:
	case FINISHED_START:
		update_msg_hash(c->msg_hash, &r, d->u.f.msg_hash);
		assert(!d->depth);
		d->end = UINT32_MAX;
		GET_4(FINISHED_HEADER);
		if (r.p[0] != FINISHED) {
			return CRYPTO_ERROR;
		}
		d->u.f.len = big_24(r.p + 1);
		d->end = (unsigned)(r.off + d->u.f.len);
		if (d->u.f.len > sizeof(d->u.f.fin)) {
			return CRYPTO_ERROR;
		}
		GET_BYTES(d->u.f.fin, d->u.f.len, FINISHED_DATA);
		err = check_finish(c, d->u.f.fin, d->u.f.len, d->u.f.msg_hash);
		if (err) {
			return err;
		}
		update_msg_hash(c->msg_hash, &r, d->u.f.msg_hash);
		if (c->is_client) {
			err = send_client_finished(c, d->u.f.msg_hash);
			if (err) {
				return err;
			}
		}
		handshake_finished(c);
		GOTO_LEVEL(QC_PROTECTED, FINISHED_LEVEL);
		goto start_ticket;

	start_ticket:
		// The only valid TLS record after the handshake is complete is a new ticket.
		// For now we just dump the tickets.
		assert(!d->depth);
		d->end = UINT32_MAX;
		GET_4(TICKET_HEADER);
		if (r.p[0] != NEW_SESSION_TICKET) {
			return CRYPTO_ERROR;
		}
		d->end = r.off + big_24(r.p + 1);
		GOTO_END(TICKET_DATA);
		goto start_ticket;
	}

end:
	if (err < 0) {
		return err;
	}

	if (c->msg_hash) {
		(*c->msg_hash)->update(c->msg_hash, r.base + r.start, r.off - r.start);
	} else {
		br_sha256_update(&c->msg_sha256, r.base + r.start, r.off - r.start);
		br_sha384_update(&c->msg_sha384, r.base + r.start, r.off - r.start);
	}

	return 0;
}
