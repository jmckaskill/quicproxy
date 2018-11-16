#pragma once
#include "quic.h"

void hkdf_extract(const br_hash_class *digest, const void *salt, size_t saltsz, const void *ikm, size_t ikmsz, void *out);
void hkdf_expand(const br_hash_class *digest, size_t hash_len, const void *secret, const void *info, size_t infosz, void *out, size_t outsz);
void hkdf_expand_label(const br_hash_class *digest, size_t hash_len, const void *secret, const char *label, const void *context, size_t ctxsz, void *out, size_t outsz);

void reset_keyset(qkeyset_t *k, uint64_t pktnum);

void generate_initial_secrets(const qconnection_id_t *id, qkeyset_t *client, qkeyset_t *server);
int generate_handshake_secrets(br_hash_compat_context *msgs, qslice_t client_hello, qslice_t server_hello, br_ec_public_key *pk, br_ec_private_key *sk, uint16_t cipher, qkeyset_t *client, qkeyset_t *server, uint8_t *master_secret);
void generate_protected_secrets(const br_hash_class *const *msgs, const uint8_t *master_secret, uint16_t cipher, qkeyset_t *client, qkeyset_t *server);

void encrypt_packet(qkeyset_t *k, uint64_t pktnum, uint8_t *pkt_begin, uint8_t *packet_number, uint8_t *enc_begin, uint8_t *pkt_end);
int64_t decrypt_packet(qkeyset_t *k, uint8_t *pkt_begin, uint8_t *packet_number, uint8_t *pkt_end, qslice_t *pkt_data);

#define QUIC_MAX_CERT_VERIFY_SIZE 256
size_t generate_cert_verify(bool is_client, const br_hash_class *const *msgs, uint8_t *out);
size_t generate_finish_verify(qkeyset_t *k, const br_hash_class *const *msgs, uint8_t *out);

int verify_rsa_pkcs1(const br_hash_class *digest, const uint8_t *hash_oid, br_x509_pkey *pk, qslice_t sig, const uint8_t *verify, size_t vlen);







