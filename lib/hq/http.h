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


#define HQ_PENDING SSIZE_T_MIN

typedef struct hq_stream_class hq_stream_class;
struct hq_stream_class {
	// The stream class abstracts both a source and sink of data. Data is pulled
	// from the sink through many intermediate notes to an originating source.
	// An HTTP client for example is just a filter that takes a source of data
	// (the request body) and produces a source of data (the response body) that is
	// fed into a sink. Likewise an HTTP server expects to both be a source (the 
	// request body) and a sink (the place to put the response body).

	void(*set_source)(const hq_stream_class **vt, const hq_stream_class **source);
	void(*set_sink)(const hq_stream_class **vt, const hq_stream_class **sink);

	// Source API - call these on a source node

	// Data is read from the source. The source is responsible for
	// buffering that data. Returned buffers MUST not be modified until a call to <read>.
	// This call can return:
	// +ve - number of bytes available in the returned pointer
	// 0   - end of file
	// -ve - permanent error
	// HQ_PENDING - try again after consuming data or after the <read_ready> notification
	ssize_t(*peek)(const hq_stream_class **vt, size_t off, const void **pdata);

	// Some time after reading data, the sink will have consumed the buffer. At that
	// point the sink will call this indicating the amount of data consumed. Data that
	// is consumed no longer needs to be buffered. At the same time the source
	// may compact any other data. Buffer pointers from previous read calls are no longer
	// valid.
	void(*read)(const hq_stream_class **vt, size_t sz);

	// The sink MAY stop reading from the source at any point. If reads
	// are not going to resume at a later time, the sink SHOULD call this. The source
	// then MAY stop buffering data and SHOULD tell upstream sources likewise.
	// This is not an error condition and MUST not stop the response from appearing.
	// An example is a POST that returns a file independent of the POST content.
	// As soon as we determine which file to use, we can stop the client from needing to
	// send more POST content.
	void(*finished)(const hq_stream_class **vt, int errnum);

	// Sink API - call these on a sink

	// This is used to notify a sink of an asynchronous error. The read functions (<peek>, <read>,
	// and <finished>) MUST not be called after this point. The sink MUST push this further down
	// the chain so that the end sink is notified. The sink MUST synchronously cancel any pending
	// usage of buffers from the source. To avoid reentrancy issues, this MUST not be called 
	// in a <peek> or <read> callback. Instead a synchronous error MUST be returned.
	void(*abort)(const hq_stream_class **vt, int errnum);

	// This is used to notify the sink that more data can be read. Sinks must be
	// prepared for both edge and level triggered notifications. To get a notification, the
	// sink must read enough to get a TRY_AGAIN. Sinks must also be prepared
	// for spurious notifications. This allows compression/filter streams to pass the notification
	// all the way downstream without having to peek through the upstream data to see if there 
	// is a full sync point or data after filtering.
	void(*read_ready)(const hq_stream_class **vt);
};

typedef struct hq_callback_class hq_callback_class;
struct hq_callback_class {
	void(*start_shutdown)(const hq_callback_class **vt, int errnum);
	void(*finish_shutdown)(const hq_callback_class **vt);

	size_t(*send_buffer)(const hq_callback_class **vt, void **pbuf);
	ssize_t(*send)(const hq_callback_class **vt, size_t len, const struct sockaddr *sa, socklen_t salen, tick_t *psent);

	// server callbacks
	// The server calls new_request when a new request comes in. This should return
	// a stream instance to cover the request. This is the most upstream node
	// on the server side and must be of the specified type. It can (and probably should)
	// have a downstream node attached that will later process the headers and request data.
	const hq_stream_class**(*new_request)(const hq_callback_class **vt, const hq_stream_class *request_type);

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
	void(*set_response)(const hq_callback_class **vt, const hq_stream_class **request, const hq_stream_class **response);
};



