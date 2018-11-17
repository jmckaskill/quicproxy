#pragma once
#include "quic.h"

qcertificate_t *read_pem_certs(const void *data, size_t size, size_t *pnum);
br_x509_trust_anchor *read_trust_anchors(const void *data, size_t size, size_t *pnum);
int read_pem_key(br_skey_decoder_context *skey, const void *data, size_t size);
int certificate_to_trust_anchor(br_x509_trust_anchor *ta, br_x509_certificate *xc);

