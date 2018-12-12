#pragma once
#include <cutils/socket.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct async_socket async_socket;
typedef struct async_listener async_listener;

typedef void(*async_socket_cb)(async_socket*, int flags);

struct async_socket {
	async_socket_cb cb;
	uint64_t total_read;
	uint64_t total_written;
	int fd;
	int flags;
	size_t idx;
#ifdef WIN32
	OVERLAPPED olread, olwrite;
#endif
	struct sockaddr *local;
	struct sockaddr *remote;
	socklen_t local_len;
	socklen_t remote_len;
	struct sockaddr_storage buf[2];
};

typedef void(*async_listen_cb)(async_listener*, int flags);

struct async_listener {
	async_listen_cb cb;
	async_socket *sock;
	int fd;
	size_t idx;
	bool accepted;
};

#define ASYNC_PENDING -1
#define ASYNC_SYSERROR -2
#define ASYNC_TOOMANY -3

typedef struct async_class async_class;
struct async_class {
	int32_t timeout_granularity_ns;
	int(*poll)(const async_class **vt, int timeout);
	
	// shutdown functions
	void(*close)(const async_class **vt, async_socket *s);
	void(*cancel)(const async_class **vt, async_socket *s);

	// functions to add a socket
	int(*new_socket)(const async_class **vt, async_socket *s, int family, int type, int protocol, async_socket_cb cb);
	int(*new_listener)(const async_class **vt, async_listener *ln, int family, int type, int protocol, async_listen_cb cb);

	// functions to read/write to a socket
	// These will initiate the read/write. The can return:
	// >= 0 - number of bytes transferred
	// ASYNC_PENDING - transfer is pending
	// ASYNC_SYSERROR - other error
	ssize_t(*read)(const async_class **vt, async_socket *s, char *buf, size_t len);
	ssize_t(*write)(const async_class **vt, async_socket *s, const char *buf, size_t len, const struct sockaddr *sa, socklen_t salen);
	ssize_t(*send_file)(const async_class **vt, async_socket *s, const char *header, size_t hlen, int fd, uint64_t off, size_t len);

	// function to accept another connection
	// This will return:
	// >= 0 - a connection has been accept synchronously with some number of bytes
	// ASYNC_PENDING - transfer is pending
	// ASYNC_SYSERROR - an error occurred
	int(*accept)(const async_class **vt, async_listener *ln, async_socket *s, char *buf, size_t len, async_socket_cb cb);
};

typedef struct async_tcp async_tcp;
struct async_tcp {
	ssize_t(*read)(const async_tcp **vt, char *buf, size_t len);
	size_t(*write_buffer)(const async_tcp **vt, size_t *plen);
	ssize_t(*write)(const async_tcp **vt, size_t len);
};

typedef struct async_poll async_poll;
struct async_poll {
	const async_class *vtable;
	size_t num;
	bool have_close;
	async_socket *sockets[256];
	struct pollfd pfd[256];
};

extern const async_class async_poll_vtable;
void async_init_poll(async_poll *a);

typedef struct async_epoll async_epoll;
struct async_epoll {
	const async_class *vtable;
};

typedef struct async_kqueue async_kqueue;
struct async_kqueue {
	const async_class *vtable;
};

typedef struct async_iocp async_iocp;
struct async_iocp {
	const async_class *vtable;
};