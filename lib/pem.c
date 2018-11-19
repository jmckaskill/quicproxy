#include "pem.h"
#include <cutils/str.h>
#include <cutils/vector.h>

typedef void(*append_fn)(void*, const void*, size_t);

static int pem_to_der(append_fn fn, void *user, const char *data, size_t sz, size_t *poff) {
	br_pem_decoder_context pem;
	br_pem_decoder_init(&pem);
	*poff += br_pem_decoder_push(&pem, data + *poff, sz - *poff);

	switch (br_pem_decoder_event(&pem)) {
	case BR_PEM_BEGIN_OBJ:
		break;
	case 0:
		// no error - probably end of file
		return 1;
	default:
		return -1;
	}

	br_pem_decoder_setdest(&pem, fn, user);
	*poff += br_pem_decoder_push(&pem, data + *poff, sz - *poff);
	br_pem_decoder_setdest(&pem, NULL, NULL);

	return (br_pem_decoder_event(&pem) == BR_PEM_END_OBJ) ? 0 : -1;
}

br_x509_certificate *read_pem_certs(const void *data, size_t size, size_t *pnum) {
	size_t off = 0;
	struct {
		br_x509_certificate *v;
		size_t size, cap;
	} certs = { 0 };

	while (off < size) {
		str_t der = STR_INIT;
		switch (pem_to_der((append_fn)&str_add2, &der, (char*)data, size, &off)) {
		case 1:
			goto end;
		case -1:
			str_destroy(&der);
			goto err;
		default:
			break;
		}
		br_x509_certificate *c = APPEND(&certs);
		c->data = (unsigned char*)der.c_str;
		c->data_len = der.len;
	}
end:
	*pnum = certs.size;
	return certs.v;
err:
	for (size_t i = 0; i < certs.size; i++) {
		free(certs.v[i].data);
	}
	free(certs.v);
	*pnum = 0;
	return NULL;
}

br_x509_trust_anchor *read_trust_anchors(const void *data, size_t size, size_t *pnum) {
	struct {
		br_x509_trust_anchor *v;
		size_t size, caps;
	} tav = { 0 };

	size_t off = 0;
	while (off < size) {
		str_t mem = STR_INIT;
		br_x509_decoder_context dc;
		br_x509_decoder_init(&dc, (append_fn)&str_add2, &mem);
		switch (pem_to_der((append_fn)&br_x509_decoder_push, &dc, (char*)data, size, &off)) {
		case 1:
			goto end;
		case -1:
			str_destroy(&mem);
			goto err;
		default:
			break;
		}

		br_x509_pkey *pk = br_x509_decoder_get_pkey(&dc);
		if (pk == NULL) {
			str_destroy(&mem);
			goto err;
		}

		br_x509_trust_anchor *ta = APPEND(&tav);
		ta->dn.len = mem.len;
		ta->flags = 0;
		if (br_x509_decoder_isCA(&dc)) {
			ta->flags |= BR_X509_TA_CA;
		}
		uint8_t *p;
		switch (pk->key_type) {
		case BR_KEYTYPE_RSA:
			ta->pkey.key_type = BR_KEYTYPE_RSA;
			ta->pkey.key.rsa.nlen = pk->key.rsa.nlen;
			ta->pkey.key.rsa.elen = pk->key.rsa.elen;
			str_add2(&mem, (char*)pk->key.rsa.n, pk->key.rsa.nlen);
			str_add2(&mem, (char*)pk->key.rsa.e, pk->key.rsa.elen);
			p = (uint8_t*)mem.c_str;
			ta->dn.data = p;
			p += ta->dn.len;
			ta->pkey.key.rsa.n = p;
			p += ta->pkey.key.rsa.nlen;
			ta->pkey.key.rsa.e = p;
			break;
		case BR_KEYTYPE_EC:
			ta->pkey.key_type = BR_KEYTYPE_EC;
			ta->pkey.key.ec.curve = pk->key.ec.curve;
			ta->pkey.key.ec.qlen = pk->key.ec.qlen;
			str_add2(&mem, (char*)pk->key.ec.q, pk->key.ec.qlen);
			p = (uint8_t*)mem.c_str;
			ta->dn.data = p;
			ta->pkey.key.ec.q = p + ta->dn.len;
			break;
		default:
			str_destroy(&mem);
			goto err;
		}
	}
end:
	*pnum = tav.size;
	return tav.v;
err:
	for (size_t i = 0; i < tav.size; i++) {
		free(tav.v[i].dn.data);
	}
	free(tav.v);
	*pnum = 0;
	return NULL;
}

int read_pem_key(br_skey_decoder_context *skey, const void *data, size_t size) {
	size_t off = 0;
	br_skey_decoder_init(skey);
	switch (pem_to_der((append_fn)&br_skey_decoder_push, skey, (char*)data, size, &off)) {
	case 0:
		return br_skey_decoder_last_error(skey);
	default:
		return -1; // no key in file or parse error
	}
}
