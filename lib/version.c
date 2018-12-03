#include "internal.h"

uint32_t QUIC_VERSIONS[] = {
	QUIC_VERSION,
	QUIC_GREASE_VERSION,
	0,
};

size_t q_encode_version(qconnect_request_t *req, void *buf, size_t bufsz) {
	const uint32_t *ver = req->server_cfg->versions ? req->server_cfg->versions : QUIC_VERSIONS;
	size_t num = 0;
	while (ver[num]) {
		num++;
	}
	if (1 + 4 + 1 + req->server[0] + req->client[0] + num * 4 > bufsz) {
		return 0;
	}
	uint8_t *p = buf;
	*(p++) = 0xE3;
	p = write_big_32(p, 0);
	*(p++) = (encode_id_len(req->client[0]) << 4) | encode_id_len(req->server[0]);
	p = append(p, req->client + 1, req->client[0]);
	p = append(p, req->server + 1, req->server[0]);
	for (size_t i = 0; i < num; i++) {
		p = write_big_32(p, ver[i]);
	}
	return (size_t)(p - (uint8_t*)buf);
}

void q_process_version(struct client_handshake *ch, qslice_t s, tick_t now) {
	size_t n = (s.e - s.p) / 4;
	struct connection *c = &ch->h.c;
	const uint32_t *our_ver = c->local_cfg->versions ? c->local_cfg->versions : QUIC_VERSIONS;
	while (*our_ver) {
		for (size_t i = 0; i < n; i++) {
			if (*our_ver == big_32(s.p + 4 * i)) {
				ch->initial_version = c->version;
				c->version = *our_ver;
				q_send_client_hello(ch, now);
				return;
			}
		}
		our_ver++;
	}
	q_internal_shutdown(&ch->h.c, QC_ERR_VERSION_NEGOTIATION, now);
}

