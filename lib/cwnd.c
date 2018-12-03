#include "internal.h"

bool q_cwnd_allow(struct connection *c) {
	return c->bytes_in_flight + DEFAULT_PACKET_SIZE / 2 < c->congestion_window;
}

/*
	At the beginning of the connection, initialize the congestion control
	variables as follows:

	  congestion_window = kInitialWindow
	  bytes_in_flight = 0
	  end_of_recovery = 0
	  ssthresh = infinite
	  ecn_ce_counter = 0
*/

void q_cwnd_init(struct connection *c) {
	c->congestion_window = INITIAL_WINDOW;
	c->bytes_in_flight = 0;
	c->after_recovery = 0;
	c->slow_start_threshold = UINT64_MAX;
}

static size_t packet_bytes(const qtx_packet_t *pkt) {
	size_t datasz = q_scheduler_cwnd_size(pkt) + q_stream_cwnd_size(pkt) + q_path_cwnd_size(pkt);
	if (!datasz) {
		return 0;
	}
	size_t ack_size = 10; // rough ballpark average as we don't keep track of the actual size
	return datasz + 1 + DEFAULT_SERVER_ID_LEN + ack_size + QUIC_TAG_SIZE;
}

/*
	InRecovery(packet_number) :
		return packet_number <= end_of_recovery
*/

static bool in_recovery(struct connection *c, uint64_t pktnum) {
	return pktnum < c->after_recovery;
}

/*
	Whenever a packet is sent, and it contains non-ACK frames, the packet
	increases bytes_in_flight.

	  OnPacketSentCC(bytes_sent):
		bytes_in_flight += bytes_sent
*/

void q_cwnd_sent(struct connection *c, const qtx_packet_t *pkt) {
	c->bytes_in_flight += packet_bytes(pkt);
}
/*
	OnPacketAckedCC(acked_packet) :
	// Remove from bytes_in_flight.
	bytes_in_flight -= acked_packet.bytes
	if (InRecovery(acked_packet.packet_number)) :
		// Do not increase congestion window in recovery period.
		return
		if (congestion_window < ssthresh) :
			// Slow start.
			congestion_window += acked_packet.bytes
		else:
			// Congestion avoidance.
			congestion_window += kMaxDatagramSize * acked_packet.bytes / congestion_window
*/

void q_ack_cwnd(struct connection *c, uint64_t pktnum, const qtx_packet_t *pkt) {
	bool before = q_cwnd_allow(c);
	size_t bytes = packet_bytes(pkt);
	c->bytes_in_flight -= bytes;
	if (in_recovery(c, pktnum)) {
		// Recovery
	} else if (c->congestion_window < c->slow_start_threshold) {
		// Slow Start
		c->congestion_window += bytes;
	} else {
		// Congestion Avoidance
		c->congestion_window += (DEFAULT_PACKET_SIZE * bytes) / c->congestion_window;
	}
	if (!before && q_cwnd_allow(c)) {
		q_async_send_data(c);
	}
}

/*
 CongestionEvent(packet_number):
		// Start a new congestion event if packet_number
		// is larger than the end of the previous recovery epoch.
		if (!InRecovery(packet_number)):
		  end_of_recovery = largest_sent_packet
		  congestion_window *= kLossReductionFactor
		  congestion_window = max(congestion_window, kMinimumWindow)
		  ssthresh = congestion_window
*/

static void congestion_event(struct connection *c, uint64_t pktnum) {
	if (!in_recovery(c, pktnum)) {
		c->after_recovery = c->prot_pkts.tx_next;
		c->congestion_window = MAX(c->congestion_window / 2, MIN_WINDOW);
		c->slow_start_threshold = c->congestion_window;
	}
}

/*
   Invoked when an ACK frame with an ECN section is received from the
   peer.

	  ProcessECN(ack):
		// If the ECN-CE counter reported by the peer has increased,
		// this could be a new congestion event.
		if (ack.ce_counter > ecn_ce_counter):
		  ecn_ce_counter = ack.ce_counter
		  // Start a new congestion event if the last acknowledged
		  // packet is past the end of the previous recovery epoch.
		  CongestionEvent(ack.largest_acked_packet)
*/
void q_cwnd_ecn(struct connection *c, uint64_t pktnum, uint64_t ecn_ce) {
	if (ecn_ce > c->ecn_ce_counter) {
		c->ecn_ce_counter = ecn_ce;
		congestion_event(c, pktnum);
	}
}

/*
   Invoked by loss detection from DetectLostPackets when new packets are
   detected lost.

	  OnPacketsLost(lost_packets):
		// Remove lost packets from bytes_in_flight.
		for (lost_packet : lost_packets):
		  bytes_in_flight -= lost_packet.bytes
		largest_lost_packet = lost_packets.last()

		// Start a new congestion epoch if the last lost packet
		// is past the end of the previous recovery epoch.
		CongestionEvent(largest_lost_packet.packet_number)
*/
void q_lost_cwnd(struct connection *c, const qtx_packet_t *pkt) {
	c->bytes_in_flight -= packet_bytes(pkt);
}

void q_cwnd_largest_lost(struct connection *c, uint64_t pktnum) {
	congestion_event(c, pktnum);
}

/*
	QUIC decreases the congestion window to the minimum value once the
	retransmission timeout has been verified and removes any packets sent
	before the newly acknowledged RTO packet.

	  OnRetransmissionTimeoutVerified(packet_number)
		congestion_window = kMinimumWindow
		// Declare all packets prior to packet_number lost.
		for (sent_packet: sent_packets):
		  if (sent_packet.packet_number < packet_number):
			bytes_in_flight -= sent_packet.bytes
			sent_packets.remove(sent_packet.packet_number)
*/
void q_cwnd_rto_verified(struct connection *c, uint64_t pktnum) {
	c->congestion_window = MIN_WINDOW;
}





