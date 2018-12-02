#include "internal.h"

size_t q_sockaddr_aad(uint8_t *o, const struct sockaddr *sa, socklen_t salen) {
	uint8_t *begin = o;
	switch (sa->sa_family) {
	case AF_INET6: {
		struct sockaddr_in6 *sa6 = (struct sockaddr_in6*) sa;
		*(o++) = AF_INET6;
		o = append(o, &sa6->sin6_addr, sizeof(sa6->sin6_addr));
		o = append(o, &sa6->sin6_port, sizeof(sa6->sin6_port));
		o = append(o, &sa6->sin6_scope_id, sizeof(sa6->sin6_scope_id)); // include the interface id for link-local addresses
		return (size_t)(o - begin);
	}
	case AF_INET: {
		struct sockaddr_in *sa4 = (struct sockaddr_in*) sa;
		*(o++) = AF_INET;
		o = append(o, &sa4->sin_addr, sizeof(sa4->sin_addr));
		o = append(o, &sa4->sin_port, sizeof(sa4->sin_port));
		return (size_t)(o - begin);
	}
	default:
		assert(0);
		return 0;
	}
}

struct retry_token {
	uint8_t version;
	uint8_t tick[4];
	uint8_t client[QUIC_ADDRESS_SIZE];
	uint8_t server[QUIC_ADDRESS_SIZE];
	uint8_t orig_server[QUIC_ADDRESS_SIZE];
	uint8_t tag[QUIC_TAG_SIZE];
};

int q_encode_retry(qconnect_request_t *req, void *buf, size_t bufsz) {
	qslice_t s;
	s.p = buf;
	s.e = s.p + bufsz;
	if (s.p + 1 + 4 + 3 * QUIC_ADDRESS_SIZE + sizeof(struct retry_token) > s.e) {
		return 0;
	}

	const qcipher_class **k = req->server_cfg->server_key;
	uint8_t aad[sizeof(struct sockaddr_storage)];
	size_t aad_len = q_sockaddr_aad(aad, req->sa, req->salen);

	// packet header
	*(s.p++) = RETRY_PACKET;
	s.p = write_big_32(s.p, req->version);

	// peer & local ids
	*(s.p++) = (encode_id_len(req->client[0]) << 4) | encode_id_len(DEFAULT_SERVER_ID_LEN);
	s.p = append(s.p, req->client + 1, req->client[0]);
	uint8_t *server_id = s.p;
	s.p += DEFAULT_SERVER_ID_LEN;

	// original destination
	*(s.p++) = 0xE0 | encode_id_len(req->server[0]);
	s.p = append(s.p, req->server + 1, req->server[0]);

	// token data: timestamp & original destination
	struct retry_token *tok = (struct retry_token*)s.p;
	tok->version = RETRY_TOKEN_IV;
	write_little_32(tok->tick, req->rxtime);
	memcpy(tok->client, req->client, QUIC_ADDRESS_SIZE);
	memcpy(tok->orig_server, req->server, QUIC_ADDRESS_SIZE);
	tok->server[0] = DEFAULT_SERVER_ID_LEN;
	memset(tok->server+1, 0, QUIC_ADDRESS_SIZE-1);
	memcpy(server_id, tok->server + 1, DEFAULT_SERVER_ID_LEN);

	// generate the new ID as a hash over the raw token data and associated data
	br_hash_compat_context h;
	(*k)->hash->init(&h.vtable);
	(*k)->hash->update(&h.vtable, aad, aad_len);
	(*k)->hash->update(&h.vtable, &tok->version, sizeof(*tok) - QUIC_TAG_SIZE);
	uint8_t newid[QUIC_MAX_HASH_SIZE];
	(*k)->hash->out(&h.vtable, newid);

	memcpy(tok->server + 1, newid, DEFAULT_SERVER_ID_LEN);
	memcpy(server_id, newid, DEFAULT_SERVER_ID_LEN);

	// encrypt the token using the socket address as additional data
	(*k)->encrypt(k, RETRY_TOKEN_IV, aad, aad_len, &tok->version, tok->tag);
	s.p += sizeof(*tok);

	return (size_t)(s.p - (uint8_t*)buf);
}

bool q_is_retry_valid(qconnect_request_t *req, const uint8_t *data, size_t len) {
	struct retry_token tok;
	if (len != sizeof(tok)) {
		return false;
	}
	memcpy(&tok, data, len);
	uint8_t aad[sizeof(struct sockaddr_storage)];
	size_t aad_len = q_sockaddr_aad(aad, req->sa, req->salen);
	if ((*req->server_cfg->server_key)->decrypt(req->server_cfg->server_key, RETRY_TOKEN_IV, aad, aad_len, &tok.version, tok.tag)) {
		return false;
	}
	if (tok.version != RETRY_TOKEN_IV || memcmp(tok.client, req->client, QUIC_ADDRESS_SIZE) || memcmp(tok.server, req->server, QUIC_ADDRESS_SIZE)) {
		return false;
	}
	tickdiff_t delta = (tickdiff_t)(req->rxtime - little_32(tok.tick));
	if (delta < 0 || delta > QUIC_TOKEN_TIMEOUT) {
		return false;
	}
	memcpy(req->orig_server, tok.orig_server, QUIC_ADDRESS_SIZE);
	return true;
}

void q_process_retry(struct client_handshake *ch, uint8_t scil, const uint8_t *source, qslice_t s, tick_t now) {
	if (s.p + 1 > s.e) {
		return;
	}
	uint8_t odcil = decode_id_len(*(s.p++) & 0xF);
	if (s.p + odcil > s.e || odcil != ch->h.c.peer_id[0] || memcmp(s.p, ch->h.c.peer_id + 1, odcil)) {
		return;
	}
	s.p += odcil;
	if ((size_t)(s.e - s.p) > sizeof(ch->token)) {
		q_internal_shutdown(&ch->h.c, QC_ERR_INTERNAL, now);
		return;
	}
	memcpy(ch->h.original_destination, ch->h.c.peer_id, QUIC_ADDRESS_SIZE);
	ch->h.c.peer_id[0] = scil;
	memcpy(ch->h.c.peer_id + 1, source, scil);
	memset(ch->h.c.peer_id + 1 + scil, 0, QUIC_ADDRESS_SIZE - scil - 1);
	ch->token_size = (uint8_t)(s.e - s.p);
	memcpy(ch->token, s.p, ch->token_size);
	q_send_client_hello(ch, &now);
}
