#include "internal.h"

static bool sockaddr_equals(const struct sockaddr *sa, const struct sockaddr *sb) {
	if (sa->sa_family != sb->sa_family) {
		return false;
	}
	switch (sa->sa_family) {
	case AF_INET: {
		const struct sockaddr_in *sa4 = (const struct sockaddr_in*)sa;
		const struct sockaddr_in *sb4 = (const struct sockaddr_in*)sb;
		return sa4->sin_addr.s_addr == sb4->sin_addr.s_addr
			&& sa4->sin_port == sb4->sin_port;
	}
	case AF_INET6: {
		const struct sockaddr_in6 *sa6 = (const struct sockaddr_in6*)sa;
		const struct sockaddr_in6 *sb6 = (const struct sockaddr_in6*)sb;
		return !memcmp(&sa6->sin6_addr, &sb6->sin6_addr, sizeof(sa6->sin6_addr))
			&& sa6->sin6_port == sb6->sin6_port
			&& sa6->sin6_scope_id == sb6->sin6_scope_id;
	}
	default:
		assert(0);
		return true;
	}
}

static uint8_t *encode_path_challenge(struct connection *c, uint8_t *p) {
	const qcipher_class **k = c->local_cfg->server_key;
	uint8_t aad[sizeof(struct sockaddr_storage)];
	size_t aad_len = q_sockaddr_aad(aad, (struct sockaddr*)&c->addr, c->addr_len);
	(*k)->encrypt(k, PATH_CHALLENGE_IV, aad, aad_len, p, p);
	return p + 8;
}

int q_update_address(struct connection *c, uint64_t pktnum, const struct sockaddr *sa, socklen_t salen, tick_t rxtime) {
	if (pktnum < c->prot_pkts.rx_next) {
		return 0;
	}
	if (salen == c->addr_len && sockaddr_equals(sa, (struct sockaddr*)&c->addr)) {
		return 0;
	}
	if (c->is_client && !c->peer_verified && !c->addr_len) {
		memcpy(&c->addr, sa, salen);
		c->addr_len = salen;
		return 0;
	}
	if (!c->handshake_complete) {
		return QC_ERR_INVALID_MIGRATION;
	}
	memcpy(&c->addr, sa, salen);
	c->addr_len = salen;
	q_reset_cwnd(c, c->prot_pkts.tx_next);
	c->path_validated = false;
	c->challenge_sent = false;
	q_start_migration(c, rxtime);
	q_async_send_data(c);
	return 0;
}

int q_decode_path_challenge(struct connection *c, qslice_t *p) {
	if (p->p + 8 > p->e) {
		return QC_ERR_FRAME_ENCODING;
	}
	if (!c->have_path_response || memcmp(c->tx_finished, p->p, 8)) {
		memcpy(c->tx_finished, p->p, 8);
		c->have_path_response = true;
		c->path_response_sent = false;
		q_async_send_data(c);
	}
	p->p += 8;
	return 0;
}

int q_decode_path_response(struct connection *c, qslice_t *p) {
	if (p->p + 8 > p->e) {
		return QC_ERR_FRAME_ENCODING;
	}
	uint8_t test[QUIC_TAG_SIZE];
	encode_path_challenge(c, test);
	if (!memcmp(test, p->p, 8)) {
		c->path_validated = true;
	}
	p->p += 8;
	return 0;
}

uint8_t *q_encode_migration(struct connection *c, uint8_t *p, qtx_packet_t *pkt) {
	if (!c->path_validated) {
		*(p++) = PATH_CHALLENGE;
		p = encode_path_challenge(c, p);
		pkt->flags |= QPKT_PATH_CHALLENGE;
		if (!c->challenge_sent) {
			pkt->flags |= QPKT_SEND;
		}
	}
	if (c->have_path_response) {
		*(p++) = PATH_RESPONSE;
		p = append(p, c->tx_finished, 8);
		pkt->flags |= QPKT_PATH_RESPONSE;
		if (!c->path_response_sent) {
			pkt->flags |= QPKT_SEND;
		}
	}
	return p;
}

void q_commit_migration(struct connection *c, const qtx_packet_t *pkt) {
	if (pkt->flags & QPKT_PATH_CHALLENGE) {
		c->challenge_sent = true;
	}
	if (pkt->flags & QPKT_PATH_RESPONSE) {
		c->path_response_sent = true;
	}
}

void q_ack_path_response(struct connection *c) {
	c->have_path_response = false;
}

void q_lost_path_challenge(struct connection *c) {
	if (!c->path_validated) {
		c->challenge_sent = false;
		q_async_send_data(c);
	}
}





