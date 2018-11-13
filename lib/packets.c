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

uint8_t * encode_varint_backwards(uint8_t *p, uint64_t val) {
	if (val < 0x40) {
		*(--p) = (uint8_t)val;
	} else if (val < 0x4000) {
		p -= 2;	write_big_16(p, (uint16_t)val | VARINT_16);
	} else if (val < 0x40000000) {
		p -= 4; write_big_32(p, (uint32_t)val | VARINT_32);
	} else {
		p -= 8; write_big_64(p, val | VARINT_64);
	}
	return p;
}

int64_t decode_varint(uint8_t **p, uint8_t *e) {
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

uint8_t *encode_packet_number(uint8_t *p, uint64_t val, uint64_t base) {
	return write_big_32(p, (uint32_t)val | UINT32_C(0xC0000000));
}

uint8_t * encode_packet_number_backwards(uint8_t *p, uint64_t val) {
	// for now just use the 4B form
	p -= 4; write_big_32(p, (uint32_t)val | UINT32_C(0xC0000000));
	return p;
}

int64_t decode_packet_number(uint8_t **p, uint8_t *e, int64_t base) {
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

static int append_slice(uint8_t **p, uint8_t *e, slice_t data) {
	size_t have = *p - e;
	if (have < data.len + 2) {
		return -1;
	}
	*p = write_big_16(*p, (uint16_t)data.len);
	memcpy(*p, data.c_str, data.len);
	*p += data.len;
	return 0;
}

static int decode_slice(uint8_t **p, uint8_t *e, slice_t *data) {
	if (*p + 2 > e) {
		return -1;
	}
	data->len = big_16(*p);
	*p += 2;
	if (*p + data->len > e) {
		return -1;
	}
	data->c_str = (char*)*p;
	*p += data->len;
	return 0;
}

int encode_server_hello(uint8_t **pp, uint8_t *e, const struct server_hello *h) {
	// check fixed size headers - up to and including extensions list size
	uint8_t *p = *pp;
	if (p + 2 + TLS_HELLO_RANDOM_SIZE + 1 + 2 + 1 + 2 > e) {
		goto err;
	}

	// legacy version
	p = write_big_16(p, TLS_LEGACY_VERSION);

	// random field
	memcpy(p, h->random, TLS_HELLO_RANDOM_SIZE);
	p += TLS_HELLO_RANDOM_SIZE;

	// legacy session ID - not used in QUIC
	*p++ = 0;

	// cipher
	p = write_big_16(p, h->cipher);

	// compression method
	*p++ = TLS_COMPRESSION_NULL;

	// extensions
	uint8_t *extensions = p;
	p += 2;

	// supported version
	if (p + 6 > e) {
		goto err;
	}
	p = write_big_16(p, SUPPORTED_VERSIONS);
	p = write_big_16(p, 2); // extension data size
	p = write_big_16(p, TLS_VERSION);

	// key share
	if (h->key.curve) {
		if ((size_t)(e-p) < 2 + 2 + 2 + 1 + h->key.qlen) {
			goto err;
		}
		p = write_big_16(p, KEY_SHARE);
		p = write_big_16(p, (uint16_t)(2 + 2 + 1 + h->key.qlen)); // extension data size
		p = write_big_16(p, (uint16_t)h->key.curve);
		p = write_big_16(p, (uint16_t)(1 + h->key.qlen)); // key length
		*p++ = EC_KEY_UNCOMPRESSED;
		memcpy(p, h->key.q, h->key.qlen);
		p += h->key.qlen;
	}

	write_big_16(extensions, (uint16_t)(p - extensions - 2));
	*pp = p;
	return 0;
err:
	return -1;
}

int encode_client_hello(uint8_t **pp, uint8_t *e, const struct client_hello *h) {
	// check fixed size headers - up to and including cipher list size
	uint8_t *p = *pp;
	if (p + 2 + TLS_HELLO_RANDOM_SIZE + 1 + 2 > e) {
		goto err;
	}

	// legacy version
	p = write_big_16(p, TLS_LEGACY_VERSION);

	// random field
	memcpy(p, h->random, TLS_HELLO_RANDOM_SIZE);
	p += TLS_HELLO_RANDOM_SIZE;

	// legacy session ID - not used in QUIC
	*p++ = 0;

	// cipher suites
	if (append_slice(&p, e, h->ciphers)) {
		goto err;
	}

	// compression methods
	if (p + 2 > e) {
		goto err;
	}
	*p++ = 1;
	*p++ = TLS_COMPRESSION_NULL;

	// extensions size in bytes - will fill out later
	if (p + 2 > e) {
		goto err;
	}
	uint8_t *extensions = p;
	p += 2;

	// server name
	if (p + 5 > e) {
		goto err;
	}
	p = write_big_16(p, SERVER_NAME);
	p = write_big_16(p, (uint16_t)(2 + 1 + 2 + h->server_name.len));
	p = write_big_16(p, (uint16_t)(1 + 2 + h->server_name.len));
	*p++ = HOST_NAME_TYPE;
	if (append_slice(&p, e, h->server_name)) {
		goto err;
	}

	// supported groups
	if (p + 4 > e) {
		goto err;
	}
	p = write_big_16(p, SUPPORTED_GROUPS);
	p = write_big_16(p, (uint16_t)(2 + h->groups.len));
	if (append_slice(&p, e, h->groups)) {
		goto err;
	}

	// signature algorithms
	if (p + 4 > e) {
		goto err;
	}
	p = write_big_16(p, SIGNATURE_ALGORITHMS);
	p = write_big_16(p, (uint16_t)(2 + h->algorithms.len));
	if (append_slice(&p, e, h->algorithms)) {
		goto err;
	}

	// supported versions
	if (p + 9 > e) {
		goto err;
	}
	p = write_big_16(p, SUPPORTED_VERSIONS);
	p = write_big_16(p, 5); // extension length
	*p++ = 4; // list of versions length
	p = write_big_16(p, 0xFAFA); // grease
	p = write_big_16(p, TLS_VERSION);

	// key share
	if (p + 6 > e) {
		goto err;
	}
	uint8_t *ks = p; // fill out the header later once we know the length
	p += 6;
	for (const br_ec_public_key *k = h->keys; k < h->keys + h->key_num; k++) {
		if (p + 2 + 2 + 1 + k->qlen > e) {
			goto err;
		}
		p = write_big_16(p, (uint16_t)k->curve);
		p = write_big_16(p, (uint16_t)(k->qlen + 1));
		*p++ = EC_KEY_UNCOMPRESSED;
		memcpy(p, k->q, k->qlen);
		p += k->qlen;
	}
	write_big_16(ks, KEY_SHARE);
	write_big_16(ks + 2, (uint16_t)(p - ks - 4));
	write_big_16(ks + 4, (uint16_t)(p - ks - 6));
	
	write_big_16(extensions, (uint16_t)(p - extensions - 2));
	*pp = p;
	return 0;
err:
	return -1;
}

int decode_client_hello(uint8_t *p, uint8_t *e, struct client_hello *h) {
	// check fixed size headers - up to and including cipher list size
	if (p + 2 + TLS_HELLO_RANDOM_SIZE + 1 + 2 > e) {
		goto err;
	}

	h->algorithms.len = 0;
	h->ciphers.len = 0;
	h->groups.len = 0;
	h->key_num = 0;

	// legacy version
	if (big_16(p) != TLS_LEGACY_VERSION) {
		goto err;
	}
	p += 2;

	// random nonce
	h->random = p;
	p += TLS_HELLO_RANDOM_SIZE;
	if (p >= e) {
		goto err;
	}

	// legacy session
	uint8_t session_len = *(p++);
	p += session_len;
	if (p >= e) {
		goto err;
	}

	// ciphers
	if (decode_slice(&p, e, &h->ciphers)) {
		goto err;
	}

	// only null compression allowed
	if (p + 2 >= e || *(p++) != 1 || *(p++) != TLS_COMPRESSION_NULL) {
		goto err;
	}

	slice_t ext;
	if (decode_slice(&p, e, &ext)) {
		goto err;
	}
	uint8_t *ep = (uint8_t*)ext.c_str;
	uint8_t *ee = ep + ext.len;
	bool have_my_version = false;

	while (ep < ee) {
		if (ep + 2 > ee) {
			goto err;
		}
		uint16_t ext_type = big_16(ep); ep += 2;
		slice_t ext_data;
		if (decode_slice(&ep, ee, &ext_data)) {
			goto err;
		}
		uint8_t *dp = (uint8_t*)ext_data.c_str;
		uint8_t *de = dp + ext_data.len;

		switch (ext_type) {
		case SERVER_NAME: {
			slice_t names;
			if (decode_slice(&dp, de, &names)) {
				goto err;
			}
			uint8_t *np = (uint8_t*)names.c_str;
			uint8_t *ne = np + names.len;
			while (np < ne) {
				uint8_t name_type = *(np++);
				slice_t other_name;
				if (decode_slice(&np, ne, (name_type == HOST_NAME_TYPE) ? &h->server_name : &other_name)) {
					goto err;
				}
			}
			break;
		}
		case SUPPORTED_GROUPS:
			if (decode_slice(&dp, de, &h->groups) || (h->groups.len & 1)) {
				goto err;
			}
			break;
		case SIGNATURE_ALGORITHMS:
			if (decode_slice(&dp, de, &h->algorithms) || (h->algorithms.len & 1)) {
				goto err;
			}
			break;
		case SUPPORTED_VERSIONS: {
			if (!ext_data.len) {
				goto err;
			}
			uint8_t vlen = *(dp++);
			if (dp + vlen > de || (vlen & 1)) {
				goto err;
			}
			for (size_t i = 0; i < vlen / 2; i++) {
				if (big_16(&dp[2 * i]) == TLS_VERSION) {
					have_my_version = true;
				}
			}
			break;
		}
		case KEY_SHARE: {
			slice_t key_data;
			if (decode_slice(&dp, de, &key_data)) {
				goto err;
			}
			uint8_t *kp = (uint8_t*)key_data.c_str;
			uint8_t *ke = kp + key_data.len;
			while (kp < ke && h->key_num < TLS_MAX_KEY_SHARE) {
				if (kp + 2 > ke) {
					goto err;
				}
				uint16_t group = big_16(kp);
				kp += 2;
				slice_t key;
				if (decode_slice(&kp, ke, &key)) {
					goto err;
				}
				if (!key.len || key.c_str[0] != EC_KEY_UNCOMPRESSED) {
					continue;
				}
				br_ec_public_key *k = &h->keys[h->key_num++];
				k->curve = group;
				k->q = (uint8_t*)key.c_str + 1;
				k->qlen = key.len - 1;
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



