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

typedef void(*hq_notify_fn)(void* user, int error);

static inline void hq_notify(hq_notify_fn *pfn, void *user, int error) {
	hq_notify_fn fn = *pfn;
	if (fn) {
		*pfn = NULL;
		fn(user, error);
	}
}

typedef struct hq_source_class hq_source_class;
struct hq_source_class {
	void(*close)(const hq_source_class **vt, int error);
	ssize_t(*start_read)(const hq_source_class **vt, size_t off, size_t minsz, const void **pdata, hq_notify_fn cb, void *user);
	void(*finish_read)(const hq_source_class **vt, size_t seek);
};

typedef struct http_request http_request;
typedef struct hq_callback_class hq_callback_class;
typedef struct hq_connection_class hq_connection_class;

struct http_request {
	const hq_source_class *vtable;
	const hq_source_class **source;
	const hq_connection_class **connection;
	hq_notify_fn notify;
	void *notify_user;
	hq_header_table rx_hdrs, tx_hdrs;
	bool finished;
};

void init_http_request(http_request *r);

struct hq_callback_class {
	void(*free_connection)(const hq_callback_class **vt, const hq_connection_class **c);
	http_request*(*next_request)(const hq_callback_class **vt);
	void(*request_finished)(const hq_callback_class **vt, http_request *r, int errnum);
};

struct hq_connection_class {
	ssize_t(*start_read_request)(const hq_connection_class **vt, http_request *request, size_t off, size_t minsz, const void **pdata);
	void(*finish_read_request)(const hq_connection_class **vt, http_request *request, size_t seek);
};

typedef void(*hq_free_cb)(void*);

typedef struct hq_listen_class hq_listen_class;
struct hq_listen_class {
	void(*close)(const hq_listen_class **vt);
	const hq_source_class **(*accept)(const hq_listen_class **vt, char *buf, size_t bufsz, struct sockaddr *remote, socklen_t *salen, const hq_source_class **source, hq_notify_fn cb, void *user);
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

