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
	if (!salen) {
		// application doesn't support migration
		return 0;
	} else if (pktnum < c->prot_pkts.rx_next) {
		// not the most recent packet
		return 0;
	} else if (c->flags & QC_CLOSING) {
		// ignore migrations on closing, at worst the remote will time out
		return 0;
	} else if (salen == c->addr_len && sockaddr_equals(sa, (struct sockaddr*)&c->addr)) {
		// address has not changed
		return 0;
	} else if ((c->flags & (QC_IS_SERVER | QC_HS_COMPLETE)) == 0 && !c->addr_len) {
		// Happy eyeballs returned the first address
		memcpy(&c->addr, sa, salen);
		c->addr_len = salen;
		return 0;
	} else if (!(c->flags & QC_HS_COMPLETE)) {
		// only allowed to migrate once the handshake is complete
		return QC_ERR_INVALID_MIGRATION;
	}
	memcpy(&c->addr, sa, salen);
	c->addr_len = salen;
	c->flags |= QC_MIGRATING | QC_PATH_CHALLENGE_SEND;
	q_reset_cwnd(c, c->prot_pkts.tx_next);
	q_start_migration(c, rxtime);
	q_async_send_data(c);
	return 0;
}

int q_decode_path_challenge(struct connection *c, qslice_t *p) {
	if (p->p + 8 > p->e) {
		return QC_ERR_FRAME_ENCODING;
	}
	if (c->flags & QC_CLOSING) {
		// ignore migrations whilst closing
	} else if (!(c->flags & QC_HAVE_PATH_CHALLENGE) || memcmp(c->tx_finished, p->p, 8)) {
		memcpy(c->tx_finished, p->p, 8);
		c->flags |= QC_HAVE_PATH_CHALLENGE | QC_PATH_RESPONSE_SEND;
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
		c->flags &= ~QC_MIGRATING;
	}
	p->p += 8;
	return 0;
}

int q_decode_new_id(struct connection *c, qslice_t *p) {
	if (p->p == p->e) {
		return QC_ERR_FRAME_ENCODING;
	}
	size_t len = *(p->p++);
	uint64_t seqnum;
	if (q_decode_varint(p, &seqnum) || len < 4 || len > 18 || p->p + len + 16 > p->e) {
		return QC_ERR_FRAME_ENCODING;
	}
	p->p += len + 16;
	LOG(c->local_cfg->debug, "RX NEW ID Seq %"PRIu64, seqnum);
	return 0;
}

int q_decode_retire_id(struct connection *c, qslice_t *p) {
	uint64_t seqnum;
	if (q_decode_varint(p, &seqnum)) {
		return QC_ERR_FRAME_ENCODING;
	}
	LOG(c->local_cfg->debug, "RX RETIRE ID Seq %"PRIu64, seqnum);
	return 0;
}

int q_decode_new_token(struct connection *c, qslice_t *p) {
	uint64_t len;
	if (q_decode_varint(p, &len) || len > (uint64_t)(p->e - p->p)) {
		return QC_ERR_FRAME_ENCODING;
	}
	p->p += (size_t)len;
	return 0;
}

uint8_t *q_encode_migration(struct connection *c, uint8_t *p, qtx_packet_t *pkt) {
	if (c->flags & QC_MIGRATING) {
		*(p++) = PATH_CHALLENGE;
		p = encode_path_challenge(c, p);
		pkt->flags |= QPKT_PATH_CHALLENGE;
		if (c->flags & QC_PATH_CHALLENGE_SEND) {
			pkt->flags |= QPKT_SEND;
		}
	}
	if (c->flags & QC_HAVE_PATH_CHALLENGE) {
		*(p++) = PATH_RESPONSE;
		p = append_mem(p, c->tx_finished, 8);
		pkt->flags |= QPKT_PATH_RESPONSE;
		if (c->flags & QC_PATH_RESPONSE_SEND) {
			pkt->flags |= QPKT_SEND;
		}
	}
	return p;
}

void q_commit_migration(struct connection *c, const qtx_packet_t *pkt) {
	if (pkt->flags & QPKT_PATH_CHALLENGE) {
		c->flags &= ~QC_PATH_CHALLENGE_SEND;
	}
	if (pkt->flags & QPKT_PATH_RESPONSE) {
		c->flags &= ~QC_PATH_RESPONSE_SEND;
	}
}

void q_ack_path_response(struct connection *c) {
	c->flags &= ~QC_HAVE_PATH_CHALLENGE;
}

void q_lost_path_challenge(struct connection *c) {
	if ((c->flags & QC_MIGRATING) && !(c->flags & QC_CLOSING)) {
		c->flags |= QC_PATH_CHALLENGE_SEND;
		q_async_send_data(c);
	}
}





