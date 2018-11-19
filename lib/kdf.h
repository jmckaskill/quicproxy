#pragma once
#include "common.h"
#include "cipher.h"

void generate_initial_secrets(const uint8_t *id, qkeyset_t *client, qkeyset_t *server);
int generate_handshake_secrets(const qcipher_class *cipher, const br_hash_class *const *msgs, const br_ec_public_key *pk, const br_ec_private_key *sk, qkeyset_t *client, qkeyset_t *server, uint8_t *master_secret);
void generate_protected_secrets(const qcipher_class *cipher, const br_hash_class *const *msgs, const uint8_t *master_secret, qkeyset_t *client, qkeyset_t *server);

#define QUIC_MAX_CERT_VERIFY_SIZE 256
size_t generate_cert_verify(const br_hash_class *digest, bool is_client, const uint8_t *msg_hash, uint8_t *out);
size_t generate_finish_verify(qkeyset_t *k, const uint8_t *msg_hash, uint8_t *out);








