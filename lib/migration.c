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

int q_update_address(struct connection *c, uint64_t pktnum, const struct sockaddr *sa, socklen_t salen) {
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
	q_cwnd_init(c);
	c->rttvar = 0;
	c->have_srtt = false;
	c->srtt = QUIC_DEFAULT_RTT;
	c->path_validated = false;
	c->challenge_sent = false;
	c->next_rtt_pktnum = c->prot_pkts.tx_next;
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

bool q_pending_migration(struct connection *c) {
	return (!c->path_validated && !c->challenge_sent)
		|| (c->have_path_response && !c->path_response_sent);
}

uint8_t *q_encode_migration(struct connection *c, uint8_t *p, qtx_packet_t *pkt) {
	if (!c->path_validated) {
		*(p++) = PATH_CHALLENGE;
		p = encode_path_challenge(c, p);
		pkt->flags |= QPKT_PATH_CHALLENGE | QPKT_RETRANSMIT;
	}
	if (c->have_path_response) {
		*(p++) = PATH_RESPONSE;
		p = append(p, c->tx_finished, 8);
		pkt->flags |= QPKT_PATH_RESPONSE;
	}
	return p;
}

void q_commit_migration(struct connection *c, const qtx_packet_t *pkt) {
	if (pkt->flags & QPKT_PATH_CHALLENGE) {
		c->challenge_sent = true;
	}
	if (c->have_path_response) {
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

size_t q_path_cwnd_size(const qtx_packet_t *pkt) {
	size_t ret = 0;
	if (pkt->flags & QPKT_PATH_CHALLENGE) {
		ret += 9;
	}
	if (pkt->flags & QPKT_PATH_RESPONSE) {
		ret += 9;
	}
	return ret;
}






