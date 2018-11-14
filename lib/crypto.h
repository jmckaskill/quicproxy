#pragma once
#include "quic.h"

void hkdf_extract(const br_hash_class *digest, const void *salt, size_t saltsz, const void *ikm, size_t ikmsz, void *out);
void hkdf_expand(const br_hash_class *digest, const void *secret, const void *info, size_t infosz, void *out, size_t outsz);
void hkdf_expand_label(const br_hash_class *digest, const void *secret, const char *label, const void *context, size_t ctxsz, void *out, size_t outsz);

void init_keyset(qkeyset_t *k);
void reset_keyset(qkeyset_t *k, uint64_t pktnum);

int init_message_hash(br_hash_compat_context *h, uint16_t cipher);
void generate_initial_secrets(const qconnection_id_t *id, qkeyset_t *client, qkeyset_t *server);
int generate_handshake_secrets(const br_hash_class *const *msgs, br_ec_public_key *pk, br_ec_private_key *sk, uint16_t cipher, qkeyset_t *client, qkeyset_t *server, uint8_t *master_secret);

void encrypt_packet(qkeyset_t *k, uint64_t pktnum, uint8_t *pkt_begin, uint8_t *packet_number, uint8_t *enc_begin, uint8_t *pkt_end);
int64_t decrypt_packet(qkeyset_t *k, uint8_t *pkt_begin, uint8_t *packet_number, uint8_t *pkt_end, qslice_t *pkt_data);



