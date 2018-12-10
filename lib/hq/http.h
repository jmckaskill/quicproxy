#pragma once
#include "qpack.h"
#include <cutils/socket.h>
#include <cutils/apc.h>

// create a connection object
// create a request
// push a bunch of headers at the request
// this encodes them ready for sending
// assign the request to the connection
// this buffers the request pending the connection being open
// for HTTP/1.1, that's when the socket becomes connected
// for HTTP/2, once the TLS handshake finishes
// for HTTP/QUIC, once the handshake finishes
// Once the request has been assigned to a connection, it sits pending
// and will send as soon as we can. This could be extended to multi
// connection pools if we wanted to.
// When creating the connection we can use a interface that has implementations for:
// - HTTP/1.0 & 1.1 (single & pooled)
// - HTTP/2
// - HTTP/QUIC
// The interface would need to have
// init
// shutdown
// flush stream
// receive
// And a callback interface with
// closed
// shutdown
// send
// new_request
// free_request
// data_sent
// data_received


#define HQ_TRY_AGAIN SSIZE_T_MIN

typedef struct hq_stream_class hq_stream_class;
struct hq_stream_class {
	size_t context_size;
	void(*init)(const hq_stream_class **vt, const hq_stream_class **upstream);

	// The stream class abstracts a unidirectional pipe where we pull data through
	// the pipe starting at the downstream node pulling from the upstream nodes.
	// An example where a client requests a file that is transparently compressed.
	// Client App Response <- Client Library Receiving <- Server Library Sending
	// <- Server App Compressor <- Server App File Reader <- Server App Dispatcher
	// <- Server Library Receiving <- Client Library Sending <- Client App Request

	// Upstream API - call these to get data from/notify upstream

	void(*set_downstream)(const hq_stream_class **vt, const hq_stream_class **down);

	// Data is read from the upstream node. The upstream node is responsible for
	// buffering that data. Returned buffers MUST not be modified until a call to <read>.
	// Calls of both headers and data with a variety of offsets can be intermixed.
	// These call can return:
	// +ve - number of items available in the returned pointer (bytes for <peek_data>, headers for <peek_header>)
	// 0   - no more items available
	// -ve - permanent error
	// HQ_TRY_AGAIN - try again after consuming data or after the <read_ready> notification
	const hq_header*(*peek_header)(const hq_stream_class **vt, size_t idx);
	ssize_t(*peek_data)(const hq_stream_class **vt, uint64_t off, const void **pdata);

	// Some time after reading data, the downstream node will have consumed the buffer. At that
	// point the downstream node will call this indicating the header and data offsets
	// that are completed. Any data before that point doesn't need to be buffered any longer.
	// Also data MAY be compacted/pointers moved around before the next read call.
	// <header_idx> MAY be SIZE_T_MAX indicating that all header buffers can be removed.
	void(*read)(const hq_stream_class **vt, size_t header_idx, uint64_t data_off);

	// The downstream node MAY stop reading from upstream at any point. If reads
	// are not going to resume at a later time, the downstream node SHOULD call this. The upstream
	// node then MAY stop buffering data and SHOULD tell further upstreams nodes likewise.
	// This is not an error condition and MUST not stop the response from appearing.
	// An example is a POST that returns a file independent of the POST content.
	// As soon as we determine which file to use, we can stop the client from needing to
	// send more POST content.
	void(*finished)(const hq_stream_class **vt, int errnum);



	// Downstream API - call these on the downstream object to notify downstream

	// This is used to notify downstream of an asynchronous error. The read functions (read_header,
	// read-data, consume, and finish_read) MUST not be called after this point. The downstream
	// node MUST push this further down the chain so that the end downstream node is notified.
	// The downstream node MUST synchronously cancel any pending usage of returned buffers.
	// This MUST not be called in a <peek> or <read> callback. Instead a synchronous error MUST
	// be returned.
	void(*abort)(const hq_stream_class **vt, int errnum);

	// This is used to notify downstream that more data can be read. Downstream nodes must be
	// prepared for both edge and level triggered notifications. To get a notification, the
	// downstream node must read enough to get a TRY_AGAIN. Consumers must also be prepared
	// for spurious notifications. This allows compression/filter streams to pass the notification
	// all the way downstream without having to peek through the upstream data to see if there 
	// is a full sync point or data after filtering.
	void(*read_ready)(const hq_stream_class **vt);

	int(*set_header)(const hq_stream_class **vt, const hq_header *hdr, const void *value, size_t len, int flags);
};

typedef struct hq_callback_class hq_callback_class;
struct hq_callback_class {
	void(*start_shutdown)(const hq_callback_class **vt, int errnum);
	void(*finish_shutdown)(const hq_callback_class **vt);

	size_t(*send_buffer)(const hq_callback_class **vt, void **pbuf);
	int(*send)(const hq_callback_class **vt, size_t len, const struct sockaddr *sa, socklen_t salen, tick_t *psent);

	// server callbacks
	// The server calls new_request when a new request comes in. This should return
	// a stream instance to cover the request. This is the most upstream node
	// on the server side and must be of the specified type. It can (and probably should)
	// have a downstream node attached that will later process the headers and request data.
	const hq_stream_class**(*new_request)(const hq_callback_class **vt, const hq_stream_class *request_type);

	// When the server is ready to provide a response. The application should call this to
	// hand the most downstream node to the library. The library will then begin to pull data
	// from this node.
	void(*set_response)(const hq_callback_class **vt, const hq_stream_class **request, const hq_stream_class **response);

	// Once the request has finished, the library will call this with the user supplied request
	// (most upstream) and response (most downstream) nodes for the application to clean up any
	// memory associated with the request.
	void(*free_request)(const hq_callback_class **vt, const hq_stream_class **request, const hq_stream_class **response);
};

typedef struct hq_tcp_class hq_tcp_class;
struct hq_tcp_class {
	const hq_stream_class *request;
	void(*close)(const hq_tcp_class **vt);
	void(*shutdown)(const hq_tcp_class **vt, int error);
	size_t(*received)(const hq_tcp_class **vt, const void *buf, size_t len);
	void(*add_request)(const hq_tcp_class **vt, const hq_stream_class **req);
};



