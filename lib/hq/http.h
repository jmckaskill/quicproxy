#pragma once
#include "header.h"
#include <cutils/socket.h>
#include <cutils/apc.h>

#define HQ_ERR_SUCCESS 0
#define HQ_PENDING -1
#define HQ_ERR_CLEAN_SHUTDOWN -2
#define HQ_ERR_TCP_RESET -3
#define HQ_ERR_INVALID_REQUEST -4
#define HQ_ERR_APP_RESET -5

typedef void(*hq_continue_fn)(void* user, int error);

typedef struct hq_continuation hq_continuation;
struct hq_continuation {
	hq_continue_fn fn;
	void *user;
};

static inline void hq_cancel(hq_continuation *p) {
	p->fn = NULL;
}

static inline void hq_continue(hq_continuation *p, int error) {
	hq_continue_fn fn = p->fn;
	if (fn) {
		p->fn = NULL;
		p->fn(p->user, error);
	}
}

typedef struct hq_source_class hq_source_class;
struct hq_source_class {
	void(*stop)(const hq_source_class **vt, int error);
	ssize_t(*read)(const hq_source_class **vt, size_t off, size_t minsz, const void **pdata, hq_continue_fn cb, void *user);
	void(*seek)(const hq_source_class **vt, size_t seek);
};

static inline void hq_stop(const hq_source_class ***psrc, int error) {
	const hq_source_class **src = *psrc;
	if (src) {
		*psrc = NULL;
		(*src)->stop(src, error);
	}
}

typedef struct http_request http_request;
typedef struct hq_connection_class hq_connection_class;

struct http_request {
	const hq_source_class *body;
	const hq_source_class **source;
	const hq_connection_class **connection;
	hq_continuation notify;
	hq_header_table rx_hdrs, tx_hdrs;
	bool started, finished;
};

void init_http_request(http_request *r);
void set_http_source(http_request *r, const hq_source_class **src);
int wait_http_headers(http_request *r, hq_continue_fn cb, void *user);
int wait_http_complete(http_request *r, hq_continue_fn cb, void *user);

struct hq_connection_class {
	void(*close)(const hq_connection_class **vt);

	ssize_t(*start_read_request)(const hq_connection_class **vt, http_request *request, size_t off, size_t minsz, const void **pdata);
	void(*finish_read_request)(const hq_connection_class **vt, http_request *request, size_t seek);
	void(*set_request_source)(const hq_connection_class **vt, http_request *request);

	int(*accept_request)(const hq_connection_class **vt, http_request *r, hq_continue_fn cb, void *user);
};

typedef struct hq_listen_class hq_listen_class;
struct hq_listen_class {
	void(*close)(const hq_listen_class **vt);
	const hq_source_class **(*accept)(const hq_listen_class **vt, char *buf, size_t bufsz, struct sockaddr *remote, socklen_t *salen, const hq_source_class **source, hq_continue_fn cb, void *user);
};

typedef struct hq_poll_class hq_poll_class;
struct hq_poll_class {
	int(*poll)(const hq_poll_class **vt);
	const hq_source_class **(*connect_tcp)(const hq_poll_class **vt, char *buf, size_t bufsz, const struct sockaddr *sa, socklen_t len, const hq_source_class **source);
	const hq_listen_class **(*listen_tcp)(const hq_poll_class **vt, char *buf, size_t bufsz, const struct sockaddr *sa, socklen_t len);
};

typedef struct hq_poll hq_poll;
struct hq_poll {
	const hq_poll_class *vtable;
	size_t num;
	struct hq_poll_socket *sockets[256];
	struct pollfd pfd[256];
	dispatcher_t dispatcher;
	bool dirty;
};

void hq_init_poll(hq_poll *p);

