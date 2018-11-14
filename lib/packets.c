#include "packets.h"
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
		return ((uint16_t)hdr & 0x3F) | *(s->p++);
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
		return ((uint16_t)hdr & 0x3F) | *(s->p++);
	case 3:
		if (s->p + 3 > s->e) {
			return -1;
		}
		s->p += 3;
		return (big_32(p) & UINT32_C(0x3FFFFFFF));
	}
}

static int append_slice(qslice_t *s, qslice_t data) {
	size_t len = data.e - data.p;
	size_t have = s->e - s->p;
	if (len + 2 > have) {
		return -1;
	}
	s->p = write_big_16(s->p, (uint16_t)len);
	s->p = append(s->p, data.p, len);
	return 0;
}

static int decode_slice(qslice_t *s, qslice_t *data) {
	uint8_t *p = s->p + 2;
	if (p > s->e) {
		return -1;
	}
	uint8_t *e = p + big_16(s->p);
	if (e > s->e) {
		return -1;
	}
	data->p = p;
	data->e = e;
	s->p = e;
	return 0;
}

int encode_server_hello(qslice_t *ps, const struct server_hello *h) {
	// check fixed size headers - up to and including extensions list size & tls version
	qslice_t s = *ps;
	if (s.p + 2 + TLS_HELLO_RANDOM_SIZE + 1 + 2 + 1 + 2 + 2 + 2 + 2 > s.e) {
		goto err;
	}

	// legacy version
	s.p = write_big_16(s.p, TLS_LEGACY_VERSION);

	// random field
	s.p = append(s.p, h->random, TLS_HELLO_RANDOM_SIZE);

	// legacy session ID - not used in QUIC
	*(s.p++) = 0;

	// cipher
	s.p = write_big_16(s.p, h->cipher);

	// compression method
	*(s.p++) = TLS_COMPRESSION_NULL;

	// extensions
	s.p += 2;
	uint8_t *ext_start = s.p;

	// supported version
	if (s.p + 6 > s.e) {
		goto err;
	}
	s.p = write_big_16(s.p, SUPPORTED_VERSIONS);
	s.p = write_big_16(s.p, 2); // extension data size
	s.p = write_big_16(s.p, TLS_VERSION);

	// key share
	if (h->key.curve) {
		if (s.p + 2 + 2 + 2 + 2 + 1 + h->key.qlen > s.e) {
			goto err;
		}
		s.p = write_big_16(s.p, KEY_SHARE);
		s.p = write_big_16(s.p, (uint16_t)(2 + 2 + 1 + h->key.qlen)); // extension data size
		s.p = write_big_16(s.p, (uint16_t)h->key.curve);
		s.p = write_big_16(s.p, (uint16_t)(1 + h->key.qlen)); // key length
		*(s.p++) = EC_KEY_UNCOMPRESSED;
		memcpy(s.p, h->key.q, h->key.qlen);
		s.p += h->key.qlen;
	}

	write_big_16(ext_start-2, (uint16_t)(s.p - ext_start));
	ps->p = s.p;
	return 0;
err:
	return -1;
}

int encode_client_hello(qslice_t *ps, const struct client_hello *h) {
	// check fixed entries - up to and including extension list size
	qslice_t s = *ps;
	size_t cipher_len = h->ciphers.e - h->ciphers.p;
	if (s.p + 2 + TLS_HELLO_RANDOM_SIZE + 1 + 2 + cipher_len + 2 + 2 > s.e) {
		goto err;
	}

	// legacy version
	s.p = write_big_16(s.p, TLS_LEGACY_VERSION);

	// random field
	memcpy(s.p, h->random, TLS_HELLO_RANDOM_SIZE);
	s.p += TLS_HELLO_RANDOM_SIZE;

	// legacy session ID - not used in QUIC
	*(s.p++) = 0;

	// cipher suites
	s.p = write_big_16(s.p, (uint16_t)cipher_len);
	memcpy(s.p, h->ciphers.p, cipher_len);
	s.p += cipher_len;

	// compression methods
	*(s.p++) = 1;
	*(s.p++) = TLS_COMPRESSION_NULL;

	// extensions size in bytes - will fill out later
	s.p += 2;
	uint8_t *ext_start = s.p;

	// server name
	size_t name_len = h->server_name.e - h->server_name.p;
	if (name_len) {
		if (s.p + 2+2+2+1+2 + name_len > s.e) {
			goto err;
		}
		s.p = write_big_16(s.p, SERVER_NAME);
		s.p = write_big_16(s.p, (uint16_t)(2 + 1 + 2 + name_len));
		s.p = write_big_16(s.p, (uint16_t)(1 + 2 + name_len));
		*(s.p++) = HOST_NAME_TYPE;
		s.p = write_big_16(s.p, (uint16_t)name_len);
		memcpy(s.p, h->server_name.p, name_len);
		s.p += name_len;
	}

	// supported groups
	size_t group_len = h->groups.e - h->groups.p;
	if (group_len) {
		if (s.p + 2+2+2+group_len > s.e) {
			goto err;
		}
		s.p = write_big_16(s.p, SUPPORTED_GROUPS);
		s.p = write_big_16(s.p, (uint16_t)(2 + group_len));
		s.p = write_big_16(s.p, (uint16_t)(group_len));
		memcpy(s.p, h->groups.p, group_len);
		s.p += group_len;
	}

	// signature algorithms
	size_t algo_len = h->algorithms.e - h->algorithms.p;
	if (algo_len) {
		if (s.p + 2 + 2 + 2 + algo_len > s.e) {
			goto err;
		}
		s.p = write_big_16(s.p, SIGNATURE_ALGORITHMS);
		s.p = write_big_16(s.p, (uint16_t)(2 + algo_len));
		s.p = write_big_16(s.p, (uint16_t)(algo_len));
		memcpy(s.p, h->algorithms.p, algo_len);
		s.p += algo_len;
	}

	// supported versions
	if (s.p + 2 + 2 + 1 + 2 + 2 > s.e) {
		goto err;
	}
	s.p = write_big_16(s.p, SUPPORTED_VERSIONS);
	s.p = write_big_16(s.p, 5); // extension length
	*(s.p++) = 4; // list of versions length
	s.p = write_big_16(s.p, 0xFAFA); // grease
	s.p = write_big_16(s.p, TLS_VERSION);

	// key share
	if (h->key_num) {
		if (s.p + 6 > s.e) {
			goto err;
		}
		uint8_t *ks = s.p;
		s.p += 6; // fill out the header later once we know the length
		for (const br_ec_public_key *k = h->keys; k < h->keys + h->key_num; k++) {
			if (s.p + 2 + 2 + 1 + k->qlen > s.e) {
				goto err;
			}
			s.p = write_big_16(s.p, (uint16_t)k->curve);
			s.p = write_big_16(s.p, (uint16_t)(k->qlen + 1));
			*(s.p++) = EC_KEY_UNCOMPRESSED;
			memcpy(s.p, k->q, k->qlen);
			s.p += k->qlen;
		}
		write_big_16(ks, KEY_SHARE);
		write_big_16(ks + 2, (uint16_t)(s.p - ks - 4));
		write_big_16(ks + 4, (uint16_t)(s.p - ks - 6));
	}
	
	write_big_16(ext_start-2, (uint16_t)(s.p - ext_start));
	ps->p = s.p;
	return 0;
err:
	return -1;
}

bool next_extension(qslice_t *ext, uint16_t *ptype, qslice_t *pdata) {
	uint8_t *data = ext->p + 4;
	if (data > ext->e) {
		return false;
	}
	uint16_t ext_type = big_16(ext->p);
	size_t ext_len = big_16(ext->p + 2);
	uint8_t *end = data + ext_len;
	if (end > ext->e) {
		return false;
	}
	ext->p = end;
	*ptype = ext_type;
	pdata->p = data;
	pdata->e = end;
	return true;
}

int decode_client_hello(qslice_t s, struct client_hello *h) {
	memset(h, 0, sizeof(*h));

	// check fixed size headers - up to and including cipher list size
	if (s.p + 2 + TLS_HELLO_RANDOM_SIZE + 1 + 2 > s.e) {
		goto err;
	}

	// legacy version
	if (big_16(s.p) != TLS_LEGACY_VERSION) {
		goto err;
	}
	s.p += 2;

	// random nonce
	h->random = s.p;
	s.p += TLS_HELLO_RANDOM_SIZE;

	// legacy session - not supported in QUIC
	if (*(s.p++) != 0) {
		goto err;
	}

	// ciphers
	if (decode_slice(&s, &h->ciphers)) {
		goto err;
	}

	// only null compression allowed
	if (s.p + 2 > s.e || *(s.p++) != 1 || *(s.p++) != TLS_COMPRESSION_NULL) {
		goto err;
	}

	qslice_t extensions;
	if (decode_slice(&s, &extensions)) {
		goto err;
	}

	bool have_my_version = false;

	uint16_t type;
	qslice_t ext;
	while (next_extension(&extensions, &type, &ext)) {
		switch (type) {
		case SERVER_NAME: {
			qslice_t names;
			if (decode_slice(&ext, &names)) {
				goto err;
			}
			while (names.p < names.e) {
				uint8_t name_type = *(names.p++);
				qslice_t other_name;
				if (decode_slice(&names, (name_type == HOST_NAME_TYPE) ? &h->server_name : &other_name)) {
					goto err;
				}
			}
			break;
		}
		case SUPPORTED_GROUPS:
			if (decode_slice(&ext, &h->groups) || ((h->groups.e - h->groups.p) & 1)) {
				goto err;
			}
			break;
		case SIGNATURE_ALGORITHMS:
			if (decode_slice(&ext, &h->algorithms) || ((h->algorithms.e - h->algorithms.p) & 1)) {
				goto err;
			}
			break;
		case SUPPORTED_VERSIONS: {
			if (ext.p == ext.e) {
				goto err;
			}
			uint8_t vlen = *(ext.p++);
			if (ext.p + vlen > ext.e || (vlen & 1)) {
				goto err;
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
			if (decode_slice(&ext, &keys)) {
				goto err;
			}
			while (keys.p < keys.e && h->key_num < QUIC_MAX_KEYSHARE) {
				if (keys.p + 2 > keys.e) {
					goto err;
				}
				uint16_t group = big_16(keys.p);
				keys.p += 2;
				qslice_t key;
				if (decode_slice(&keys, &key)) {
					goto err;
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

err:
	return -1;
}

int decode_server_hello(qslice_t s, struct server_hello *h) {
	memset(h, 0, sizeof(*h));

	// check fixed size headers - up to and including extension list size
	if (s.p + 2 + TLS_HELLO_RANDOM_SIZE + 1 + 2 > s.e) {
		goto err;
	}

	// legacy version
	if (big_16(s.p) != TLS_LEGACY_VERSION) {
		goto err;
	}
	s.p += 2;

	// random nonce
	h->random = s.p;
	s.p += TLS_HELLO_RANDOM_SIZE;

	// legacy session - not supported in QUIC
	if (*(s.p++) != 0) {
		goto err;
	}

	// ciphers
	h->cipher = big_16(s.p);
	s.p += 2;

	// only null compression allowed
	if (*(s.p++) != TLS_COMPRESSION_NULL) {
		goto err;
	}

	qslice_t extensions;
	if (decode_slice(&s, &extensions)) {
		goto err;
	}

	bool have_my_version = false;

	uint16_t type;
	qslice_t ext;
	while (next_extension(&extensions, &type, &ext)) {
		switch (type) {
		case SUPPORTED_VERSIONS:
			if (ext.p + 2 <= ext.e && big_16(ext.p) == TLS_VERSION) {
				have_my_version = true;
			}
			break;
		case KEY_SHARE:
			if (ext.p + 2 + 2 <= ext.e) {
				uint16_t curve = big_16(ext.p);
				ext.p += 2;
				qslice_t key;
				if (decode_slice(&ext, &key)) {
					goto err;
				}
				if (key.p < key.e && key.p[0] == EC_KEY_UNCOMPRESSED) {
					h->key.curve = curve;
					h->key.q = key.p + 1;
					h->key.qlen = key.e - h->key.q;
				}
			}
			break;
		}
	}

	return 0;
err:
	return -1;
}



