#include "internal.h"

// Timeout calculations

static tickdiff_t rtt(const struct connection *c) {
	return c->srtt ? c->srtt : QUIC_DEFAULT_RTT;
}

static tickdiff_t retransmission_timeout(const struct connection *c, int count) {
	tickdiff_t rto = MAX(rtt(c) + 4 * c->rttvar + c->peer_cfg.max_ack_delay, QUIC_MIN_RTO_TIMEOUT);
	return (1 << count) * rto;
}

static tickdiff_t drain_timeout(const struct connection *c) {
	return 3 * retransmission_timeout(c, 0);
}

static tickdiff_t probe_timeout(const struct connection *c, int count) {
	tickdiff_t tlp = MAX((3 * rtt(c)) / 2 + c->peer_cfg.max_ack_delay, QUIC_MIN_TLP_TIMEOUT);
	tickdiff_t rto = MAX(rtt(c) + 4 * c->rttvar + c->peer_cfg.max_ack_delay, QUIC_MIN_RTO_TIMEOUT);
	return (1 << count) * MAX(tlp, rto);
}

static tickdiff_t idle_timeout(const struct connection *c) {
	return c->local_cfg->idle_timeout ? c->local_cfg->idle_timeout : QUIC_DEFAULT_IDLE_TIMEOUT;
}

static tickdiff_t handshake_timeout(const struct connection *c) {
	return idle_timeout(c) / 4;
}

static tickdiff_t path_migration_timeout(const struct connection *c) {
	return idle_timeout(c) / 4;
}

static tickdiff_t crypto_timeout(const struct connection *c, int count) {
	return (2 << count) * rtt(c);
}

static tickdiff_t close_timeout(const struct connection *c, int count) {
	return crypto_timeout(c, count);
}


// RX timer - used for retransmissions to detect lost packets
// The timers don't directly decide on loss. A packet must be sent when this timer fires.
// Handshake - timeout during handshake processing that resends all unacked crypto data
// Tail Loss Probe (TLP)
// Retransmission (RTO)
// Close - timeout waiting for the ack of a close
// Ping - idle timeout for when we don't have anything in flight

static void on_handshake_timeout(apc_t *a, tick_t now) {
	struct connection *c = container_of(a, struct connection, rx_timer);
	// ignore the error if the send fails, we'll try again next timeout
	LOG(c->local_cfg->debug, "HS timeout %d", c->rx_timer_count);
	assert(!c->peer_verified);
	if (c->is_server) {
		q_send_server_hello((struct server_handshake*)c, NULL, NULL, now);
	} else {
		q_send_client_hello((struct client_handshake*)c, NULL, now);
	}
	add_timed_apc(c->dispatcher, a, now + crypto_timeout(c, c->rx_timer_count++), &on_handshake_timeout);
	LOG(c->local_cfg->debug, "");
}

static void on_retransmission_timeout(apc_t *a, tick_t now) {
	struct connection *c = container_of(a, struct connection, rx_timer);
	LOG(c->local_cfg->debug, "RTO %d", c->rx_timer_count);
	q_send_packet(c, now, SEND_FORCE | SEND_PING);
	q_send_packet(c, now, SEND_FORCE | SEND_PING);
	add_timed_apc(c->dispatcher, a, now + retransmission_timeout(c, c->rx_timer_count++), &on_retransmission_timeout);
	LOG(c->local_cfg->debug, "");
}

static void on_probe_timeout(apc_t *a, tick_t now) {
	struct connection *c = container_of(a, struct connection, rx_timer);
	LOG(c->local_cfg->debug, "TLP %d", c->rx_timer_count);
	q_send_packet(c, now, SEND_FORCE | SEND_PING);
	if (c->rx_timer_count == 2) {
		c->rx_timer_count = 0;
		c->rto_next = c->prot_pkts.tx_next;
		add_timed_apc(c->dispatcher, a, now + retransmission_timeout(c, c->rx_timer_count++), &on_retransmission_timeout);
	} else {
		add_timed_apc(c->dispatcher, a, now + probe_timeout(c, c->rx_timer_count++), &on_probe_timeout);
	}
	LOG(c->local_cfg->debug, "");
}

static void on_ping_timeout(apc_t *a, tick_t now) {
	struct connection *c = container_of(a, struct connection, rx_timer);
	LOG(c->local_cfg->debug, "PING timeout");
	q_send_packet(c, now, SEND_FORCE | SEND_PING);
	q_reset_rx_timer(c, now);
	LOG(c->local_cfg->debug, "");
}

static void on_close_timeout(apc_t *a, tick_t now) {
	struct connection *c = container_of(a, struct connection, rx_timer);
	if (!c->draining) {
		q_send_packet(c, now, SEND_FORCE | SEND_PING);
		add_timed_apc(c->dispatcher, a, now + close_timeout(c, c->rx_timer_count++), &on_close_timeout);
	}
}

// called after receiving a new ack or sending a non-ack packet
void q_reset_rx_timer(struct connection *c, tick_t now) {
	c->rto_next = 0;
	c->rx_timer_count = 0;
	if (c->draining) {
		cancel_apc(c->dispatcher, &c->rx_timer);
	} else if (c->closing) {
		add_timed_apc(c->dispatcher, &c->rx_timer, now + close_timeout(c, c->rx_timer_count++), &on_close_timeout);
	} else if (!c->peer_verified) {
		add_timed_apc(c->dispatcher, &c->rx_timer, now + crypto_timeout(c, c->rx_timer_count++), &on_handshake_timeout);
	} else if (c->bytes_in_flight) {
		add_timed_apc(c->dispatcher, &c->rx_timer, now + probe_timeout(c, c->rx_timer_count++), &on_probe_timeout);
	} else if (c->local_cfg->ping_timeout) {
		add_timed_apc(c->dispatcher, &c->rx_timer, now + c->local_cfg->ping_timeout, &on_ping_timeout);
	} else {
		cancel_apc(c->dispatcher, &c->rx_timer);
	}
}

// ACK timer - used for delaying ack transmits

static void on_ack_timeout(apc_t *a, tick_t now) {
	struct connection *c = container_of(a, struct connection, ack_timer);
	LOG(c->local_cfg->debug, "ACK timeout");
	q_send_packet(c, now, SEND_FORCE);
	LOG(c->local_cfg->debug, "");
}

static void async_ack(struct connection *c, tick_t wakeup) {
	if (!is_apc_active(&c->ack_timer) || (tickdiff_t)(wakeup - c->ack_timer.wakeup) < 0) {
		add_timed_apc(c->dispatcher, &c->ack_timer, wakeup, &on_ack_timeout);
	}
}

void q_async_ack(struct connection *c, tick_t now) {
	async_ack(c, now + QUIC_LONG_ACK_TIMEOUT);
}

void q_fast_async_ack(struct connection *c, tick_t now) {
	async_ack(c, now + QUIC_SHORT_ACK_TIMEOUT);
}

// Flush data - used an APC to try and flush data after the current round of packets have been processed
// Packets may be sent (or not)

static void on_async_send_data(apc_t *a, tick_t now) {
	struct connection *c = container_of(a, struct connection, flush_apc);
	while (q_send_packet(c, now, 0) != NULL) {
	}
}

void q_async_send_data(struct connection *c) {
	if (!c->draining) {
		add_apc(c->dispatcher, &c->flush_apc, &on_async_send_data);
	}
}

// Idle timer - used for detecting an idle link
// Idle - during runtime
// Path - after path migration, waiting for the response
// Draining - time after starting a shutdown to consider the connection fully drained

static void on_idle_timeout(apc_t *w, tick_t now) {
	struct connection *c = container_of(w, struct connection, idle_timer);
	LOG(c->local_cfg->debug, "idle timeout");
	q_internal_shutdown(c, QC_ERR_IDLE_TIMEOUT);
}

static void on_path_timeout(apc_t *w, tick_t now) {
	struct connection *c = container_of(w, struct connection, idle_timer);
	LOG(c->local_cfg->debug, "path timeout");
	q_internal_shutdown(c, QC_ERR_INVALID_MIGRATION);
}

static void on_drained_timeout(apc_t *a, tick_t now) {
	struct connection *c = container_of(a, struct connection, idle_timer);
	LOG(c->local_cfg->debug, "drained timeout");
	qc_close((qconnection_t*)c);
	(*c->iface)->free(c->iface);
}

// called after receiving a new packet
void q_reset_idle_timer(struct connection *c, tick_t now) {
	if (!c->closing && c->peer_verified && c->path_validated) {
		add_timed_apc(c->dispatcher, &c->idle_timer, now + idle_timeout(c), &on_path_timeout);
	}
}

void q_start_migration(struct connection *c, tick_t now) {
	add_timed_apc(c->dispatcher, &c->idle_timer, now + path_migration_timeout(c), &on_path_timeout);
}

void q_start_shutdown(struct connection *c) {
	tick_t now = c->dispatcher->last_tick;
	add_timed_apc(c->dispatcher, &c->idle_timer, now + drain_timeout(c), &on_drained_timeout);
	if (!c->close_sent) {
		q_async_send_data(c);
	}
}

void q_start_handshake_timers(struct handshake *h, tick_t now) {
	struct connection *c = &h->c;
	add_timed_apc(c->dispatcher, &c->idle_timer, now + handshake_timeout(c), &on_idle_timeout);
	q_reset_rx_timer(c, now);
}

void q_start_runtime_timers(struct handshake *h, tick_t now) {
	struct connection *c = &h->c;
	if (c->is_server && !c->srtt) {
		// Client may not send any acks on initial & handshake as the client
		// is finished with those levels. Use the handshake response time
		// to initialize srtt.
		qpacket_buffer_t *b = &h->pkts[QC_HANDSHAKE];
		tick_t sent = b->sent[(b->tx_next - 1) % b->sent_len].sent;
		c->srtt = (tickdiff_t)(now - sent);
		c->rttvar = c->srtt / 2;
	}
	c->prot_pkts.sent = (qtx_packet_t*)(c + 1);
	c->prot_pkts.sent_len = (h->conn_buf_end - (uint8_t*)(c+1)) / sizeof(qtx_packet_t);
	c->peer_verified = true;
	c->path_validated = true;
	c->challenge_sent = true;
	q_update_scheduler_from_cfg(c);
	q_reset_idle_timer(c, now);
	q_reset_rx_timer(c, now);
	q_async_send_data(c);
}

void qc_move(qconnection_t *cin, dispatcher_t *d) {
	struct connection *c = (struct connection*)cin;
	if (c->dispatcher != d) {
		move_apc(c->dispatcher, d, &c->ack_timer);
		move_apc(c->dispatcher, d, &c->flush_apc);
		move_apc(c->dispatcher, d, &c->rx_timer);
		move_apc(c->dispatcher, d, &c->idle_timer);
		c->dispatcher = d;
	}
}

void qc_close(qconnection_t *cin) {
	struct connection *c = (struct connection*)cin;
	cancel_apc(c->dispatcher, &c->ack_timer);
	cancel_apc(c->dispatcher, &c->flush_apc);
	cancel_apc(c->dispatcher, &c->rx_timer);
	cancel_apc(c->dispatcher, &c->idle_timer);
}



