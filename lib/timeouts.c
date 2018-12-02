#include "internal.h"

// Timeout calculations

static tickdiff_t retransmission_timeout(const struct connection *c, int count) {
	tickdiff_t rto = MAX(c->srtt + 4 * c->rttvar + c->peer_cfg.max_ack_delay, QUIC_MIN_RTO_TIMEOUT);
	return (1 << count) * rto;
}

static tickdiff_t destroy_timeout(struct connection *c) {
	return 3 * retransmission_timeout(c, 0);
}

static tickdiff_t probe_timeout(const struct connection *c, int count) {
	tickdiff_t tlp = MAX((3 * c->srtt) / 2 + c->peer_cfg.max_ack_delay, QUIC_MIN_TLP_TIMEOUT);
	tickdiff_t rto = MAX(c->srtt + 4 * c->rttvar + c->peer_cfg.max_ack_delay, QUIC_MIN_RTO_TIMEOUT);
	return (1 << count) * MAX(tlp, rto);
}

static tickdiff_t idle_timeout(const struct connection *c) {
	return c->local_cfg->idle_timeout ? c->local_cfg->idle_timeout : QUIC_DEFAULT_IDLE_TIMEOUT;
}

static tickdiff_t handshake_timeout(const struct connection *c, int count) {
	return (2 << count) * c->srtt;
}


// RX timer - used for detecting lost packets

static void on_retransmission_timeout(apc_t *a, tick_t now) {
	struct connection *c = container_of(a, struct connection, rx_timer);
	LOG(c->local_cfg->debug, "RTO %d", c->rx_timer_count);
	c->retransmit_pktnum = c->prot_pkts.tx_next;
	q_send_data(c, 2, now);
	add_timed_apc(c->dispatcher, a, now + retransmission_timeout(c, c->rx_timer_count++), &on_retransmission_timeout);
	LOG(c->local_cfg->debug, "");
}

static void on_probe_timeout(apc_t *a, tick_t now) {
	struct connection *c = container_of(a, struct connection, rx_timer);
	LOG(c->local_cfg->debug, "TLP %d", c->rx_timer_count);
	q_send_data(c, 1, now);
	if (c->rx_timer_count == 2) {
		c->rx_timer_count = 0;
		add_timed_apc(c->dispatcher, a, now + retransmission_timeout(c, 0), &on_retransmission_timeout);
	} else {
		add_timed_apc(c->dispatcher, a, now + probe_timeout(c, c->rx_timer_count++), &on_probe_timeout);
	}
	LOG(c->local_cfg->debug, "");
}

static void on_handshake_timeout(apc_t *a, tick_t now) {
	struct connection *c = container_of(a, struct connection, rx_timer);
	// ignore the error if the send fails, we'll try again next timeout
	LOG(c->local_cfg->debug, "HS timeout %d", c->rx_timer_count);
	assert(!c->peer_verified);
	if (c->is_client) {
		q_send_client_hello((struct client_handshake*)c, &now);
	} else {
		q_send_server_hello((struct server_handshake*)c, NULL, now);
	}
	add_timed_apc(c->dispatcher, a, now + handshake_timeout(c, c->rx_timer_count++), &on_handshake_timeout);
	LOG(c->local_cfg->debug, "");
}

static void on_send_close(apc_t *a, tick_t now) {
	struct connection *c = container_of(a, struct connection, rx_timer);
	q_send_close(c, now);
	if (!c->draining) {
		add_timed_apc(c->dispatcher, &c->rx_timer, now + handshake_timeout(c, c->rx_timer_count++), &on_send_close);
	}
}

void q_start_probe_timer(struct connection *c, tick_t now) {
	assert(c->peer_verified && !c->closing);
	c->rx_timer_count = 0;
	add_timed_apc(c->dispatcher, &c->rx_timer, now + probe_timeout(c, c->rx_timer_count++), &on_probe_timeout);
}

static void start_handshake_timer(struct connection *c, tick_t now) {
	assert(!c->peer_verified && !c->closing);
	c->rx_timer_count = 0;
	add_timed_apc(c->dispatcher, &c->rx_timer, now + handshake_timeout(c, c->rx_timer_count++), &on_handshake_timeout);
}

static void start_close_timer(struct connection *c, tick_t now) {
	assert(c->closing);
	if (c->draining) {
		cancel_apc(c->dispatcher, &c->rx_timer);
	} else {
		c->rx_timer_count = 0;
		q_send_close(c, now);
		add_timed_apc(c->dispatcher, &c->rx_timer, now + handshake_timeout(c, c->rx_timer_count++), &on_send_close);
	}
}

// TX timer - used for delaying transmits for coalescing (ping, acks & send new streams)

static void on_ping_timeout(apc_t *a, tick_t now) {
	struct connection *c = container_of(a, struct connection, tx_timer);
	LOG(c->local_cfg->debug, "PING timeout");
	struct short_packet sp = {
		.force_ack = true,
		.ignore_cwnd = true,
	};
	q_send_short_packet(c, &sp, &now);
	q_start_ping_timeout(c, now);
	LOG(c->local_cfg->debug, "");
}

void q_start_ping_timeout(struct connection *c, tick_t now) {
	if (c->local_cfg->ping_timeout) {
		add_timed_apc(c->dispatcher, &c->tx_timer, now + c->local_cfg->ping_timeout, &on_ping_timeout);
	}
}

static void on_ack_timeout(apc_t *a, tick_t now) {
	struct connection *c = container_of(a, struct connection, tx_timer);
	LOG(c->local_cfg->debug, "ACK timeout");
	// try and send a packet with data
	if (q_send_data(c, 0, now) == 0) {
		// otherwise fall back to just an ack
		struct short_packet sp = {
			.ignore_cwnd = true,
			.ignore_closing = true,
			.send_ack = true,
			.send_close = c->closing,
		};
		q_send_short_packet(c, &sp, &now);
	}
	q_start_ping_timeout(c, now);
	LOG(c->local_cfg->debug, "");
}

static void async_draining_ack(apc_t *a, tick_t now) {
	struct connection *c = container_of(a, struct connection, tx_timer);
	struct short_packet sp = {
		.ignore_cwnd = true,
		.ignore_closing = true,
		.ignore_draining = true,
		.send_ack = true,
	};
	q_send_short_packet(c, &sp, &now);
}

static void async_ack(struct connection *c, tick_t wakeup) {
	if (!is_apc_active(&c->tx_timer) || (tickdiff_t)(wakeup - c->tx_timer.wakeup) < 0) {
		add_timed_apc(c->dispatcher, &c->tx_timer, wakeup, &on_ack_timeout);
	}
}

void q_async_ack(struct connection *c, tick_t now) {
	async_ack(c, now + QUIC_LONG_ACK_TIMEOUT);
}

void q_fast_async_ack(struct connection *c, tick_t now) {
	async_ack(c, now + QUIC_SHORT_ACK_TIMEOUT);
}

void q_draining_ack(struct connection *c, tick_t now) {
	add_apc(c->dispatcher, &c->tx_timer, &async_draining_ack);
}

static void on_async_send_data(apc_t *a, tick_t now) {
	struct connection *c = container_of(a, struct connection, tx_timer);
	q_send_data(c, 0, now);
	q_start_ping_timeout(c, now);
}

void q_async_send_data(struct connection *c) {
	add_apc(c->dispatcher, &c->tx_timer, &on_async_send_data);
}


// Idle timer - used for detecting an idle link


static void on_idle_timeout(apc_t *w, tick_t now) {
	struct connection *c = container_of(w, struct connection, idle_timer);
	LOG(c->local_cfg->debug, "idle timeout");
	q_internal_shutdown(c, QC_ERR_IDLE_TIMEOUT, now);
}

void q_start_idle_timer(struct connection *c, tick_t now) {
	if (!c->closing) {
		add_timed_apc(c->dispatcher, &c->idle_timer, now + idle_timeout(c), &on_idle_timeout);
	}
}

static void on_destroy_timeout(apc_t *a, tick_t now) {
	struct connection *c = container_of(a, struct connection, idle_timer);
	qc_close((qconnection_t*)c);
	(*c->iface)->close(c->iface);
}

static void async_shutdown(apc_t *a, tick_t now) {
	struct connection *c = container_of(a, struct connection, idle_timer);
	q_start_shutdown(c, now);
}

// Setup the two phases of a connection

void q_start_handshake(struct handshake *h, tick_t now) {
	start_handshake_timer(&h->c, now);
	q_start_idle_timer(&h->c, now);
	cancel_apc(h->c.dispatcher, &h->c.tx_timer);
}

void q_start_runtime(struct handshake *h, tick_t now) {
	struct connection *c = &h->c;
	if (!c->is_client) {
		// Client may not send any acks on initial & handshake as it's done
		// with those levels. Use the handshake response time to initialize
		// srtt.
		qpacket_buffer_t *b = &h->pkts[QC_HANDSHAKE];
		tick_t sent = b->sent[(b->tx_next - 1) % b->sent_len].sent;
		c->have_srtt = true;
		c->srtt = (tickdiff_t)(now - sent);
		c->rttvar = c->srtt / 2;
	}
	c->prot_pkts.sent = (qtx_packet_t*)(c + 1);
	c->prot_pkts.sent_len = (h->conn_buf_end - (uint8_t*)(c+1)) / sizeof(qtx_packet_t);
	c->peer_verified = true;
	c->path_validated = true;
	c->challenge_sent = true;
	cancel_apc(c->dispatcher, &c->rx_timer);
	q_update_scheduler_from_cfg(c);
	q_cwnd_init(c);
	q_start_idle_timer(c, now);
	q_async_send_data(c);
}

void q_start_shutdown(struct connection *c, tick_t now) {
	add_timed_apc(c->dispatcher, &c->idle_timer, now + destroy_timeout(c), &on_destroy_timeout);
	start_close_timer(c, now); // rx_timer
	// leave tx_timer as is, as it may be running the draining ack
}

void q_async_shutdown(struct connection *c) {
	add_apc(c->dispatcher, &c->idle_timer, &async_shutdown);
}


