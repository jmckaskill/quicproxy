#pragma once
#include "common.h"
#include "cipher.h"

typedef struct qtx_stream qtx_stream_t;
struct qtx_stream {
	int64_t id;
	uint64_t max_data_allowed;
	uint64_t offset;
	uint8_t *data;
	size_t len;
};

int qtx_init(qtx_stream_t *t, void *buf, size_t sz);

void *qtx_send_buffer(qtx_stream_t *t, size_t min, size_t *psz);
void qtx_send(qtx_stream_t *t, size_t sz);
void qtx_send_finish(qtx_stream_t *t);

typedef struct qtx_packet qtx_packet_t;
struct qtx_packet {
	uint64_t from, to;	// offset of this packet into the data stream
	qtx_stream_t *stream;
	tick_t sent;
};

typedef struct qpacket_buffer qpacket_buffer_t;
struct qpacket_buffer {
	qtx_packet_t *sent;	// packets sent for retries
	size_t sent_len;	// number of packets in the send buffer
	uint64_t received;	// receive bitset - one bit per packet
	uint64_t rx_next;   // next packet to receive (highest received + 1)
	uint64_t tx_next;   // next packet to send (highest sent + 1)
	qkeyset_t tkey;
	qkeyset_t rkey;
};

