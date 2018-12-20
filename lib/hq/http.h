#pragma once
#include "header.h"
#include <cutils/socket.h>
#include <cutils/apc.h>

#define HQ_ERR_SUCCESS 0
#define HQ_ERR_TCP_RESET -1
#define HQ_ERR_INVALID_REQUEST -2
#define HQ_ERR_APP_RESET -3
#define HQ_PENDING SSIZE_T_MIN

typedef struct hq_stream_class hq_stream_class;
struct hq_stream_class {
	// The stream class abstracts both a source and sink of data. Data is pulled
	// from the sink through many intermediate notes to an originating source.
	// An HTTP client for example is just a sink that takes a source of data
	// (the request body) and produces a source of data (the response body) that is
	// fed into a sink. Likewise an HTTP server expects to both be a source (the 
	// request body) and a sink (the place to put the response body).

	// Source API - call these on a source node

	// Data is read from the source. The source is responsible for
	// buffering that data. Returned buffers MUST not be modified until a call to <seek>.
	// This call can return:
	// +ve - number of bytes available in the returned pointer
	// 0   - end of file
	// -ve - permanent error
	// HQ_PENDING - try again after consuming data or after the notification
	ssize_t(*read)(const hq_stream_class **vt, const hq_stream_class **sink, size_t off, const void **pdata);

	// Some time after reading data, the sink will have consumed the buffer. At that
	// point the sink will call this indicating the amount of data consumed. Data that
	// is consumed no longer needs to be buffered. At the same time the source
	// may compact any other data. Buffer pointers from previous <peek> calls are no longer
	// valid.

	// The sink MAY stop reading from the source at any point. If reads
	// are not going to resume at a later time, the sink SHOULD call this. The source
	// then MAY stop buffering data and SHOULD tell upstream sources likewise.
	// This is not an error condition and MUST not stop the response from appearing.
	// An example is a POST that returns a file independent of the POST content.
	// As soon as we determine which file to use, we can stop the client from needing to
	// send more POST content.
	void(*finish_read)(const hq_stream_class **vt, size_t finished, int close);


	// Sink API - call these on a sink

	// This is used to notify a sink of an asynchronous error. The read functions (<peek>, <seek>,
	// and <finished>) MUST not be called after this point. The sink MUST push this further down
	// the chain so that the end sink is notified. The sink MUST synchronously cancel any pending
	// usage of buffers from the source. To avoid reentrancy issues, this MUST not be called 
	// in a <peek> or <seek> callback. Instead a synchronous error MUST be returned.

	// This is used to notify the sink that more data can be read. Sinks must be
	// prepared for both edge and level triggered notifications. To get a notification, the
	// sink must read enough to get a TRY_AGAIN. Sinks must also be prepared
	// for spurious notifications. This allows compression/filter streams to pass the notification
	// all the way downstream without having to peek through the upstream data to see if there 
	// is a full sync point or data after filtering.
	void(*notify)(const hq_stream_class **vt, const hq_stream_class **source, int close);
};

typedef struct http_request http_request;
typedef struct hq_callback_class hq_callback_class;
typedef struct hq_connection_class hq_connection_class;

struct http_request {
	const hq_stream_class *vtable;
	const hq_stream_class **source, **sink;
	const hq_connection_class **connection;
	hq_header_table req_hdrs, resp_hdrs;
};

void init_http_request(http_request *r);

struct hq_callback_class {
	void(*free_connection)(const hq_callback_class **vt, const hq_connection_class **c);
	http_request*(*next_request)(const hq_callback_class **vt);
	void(*request_finished)(const hq_callback_class **vt, http_request *r, int errnum);
};

struct hq_connection_class {
	void(*close)(const hq_connection_class **vt, int errnum);
	ssize_t(*read_request)(const hq_connection_class **vt, http_request *request, uint64_t off, const void **pdata);
	void(*finish_read_request)(const hq_connection_class **vt, http_request *request, uint64_t finished, int close);
	void(*request_ready)(const hq_connection_class **vt, http_request *request, int close);
};

typedef void(*hq_free_cb)(void*);

typedef struct hq_poll_class hq_poll_class;
struct hq_poll_class {
	void(*poll)(const hq_poll_class **vt, dispatcher_t *d, tick_t time_us);
	const hq_stream_class **(*connect_tcp)(const hq_poll_class **vt, const struct sockaddr *sa, socklen_t len, char *rxbuf, size_t bufsz, hq_free_cb free, void *user);
};

typedef struct hq_poll hq_poll;
struct hq_poll {
	const hq_poll_class *vtable;
	size_t num;
	struct hq_poll_socket *sockets[256];
	struct pollfd pfd[256];
	bool dirty;
};

void hq_init_poll(hq_poll *p);