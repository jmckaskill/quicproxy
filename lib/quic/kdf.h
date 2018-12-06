#pragma once
#include "common.h"
#include "cipher.h"

#define HANDSHAKE_CLIENT "quic c hs traffic"
#define HANDSHAKE_SERVER "quic s hs traffic"
#define PROT_CLIENT "quic c ap traffic"
#define PROT_SERVER "quic s ap traffic"

void hkdf_expand_label(void *out, size_t outsz, const br_hash_class *digest, const void *secret, const char *label, const void *msg_hash);
void derive_secret(void *derived, const br_hash_class *digest, const void *secret, const char *label, const void *msg_hash);

void init_initial_cipher(qcipher_aes_gcm *k, int is_server, const void *server_id, size_t id_len);
int calc_handshake_secret(void *secret, const br_hash_class *digest, const void *msg_hash, const br_ec_public_key *pk, const br_ec_private_key *sk);
void calc_master_secret(void *master, const br_hash_class *digest, const void *handshake);

#define QUIC_MAX_CERT_VERIFY_SIZE 256
size_t calc_cert_verify(void *out, bool is_client, const br_hash_class *digest, const void *msg_hash);
void calc_finish_verify(void *out, const br_hash_class *digest, const void *msg_hash, const void *hs_traffic);

void log_handshake(log_t *log, const br_hash_class *digest, const void *client, const void *server, const void *client_random);
void log_protected(log_t *log, const br_hash_class *digest, const void *client, const void *server, const void *client_random);






