#pragma once

#include <os/c.h>
#include <os/proc.h>
#include <os/time.h>
#include <os/log.h>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

struct sockaddr;

// all files/sockets have a type fd_t, -ve is an invalid fd
// async_t contains the async tracking data associated with
// a single fd. struct async has the following prototype
// struct async {
//  void *udata;
//  HANDLE/int fd;
//  ... internal variables
// };
// udata is not used by the library
// fd is set by the library, but may also be set by the user

struct async;
typedef struct async async_t;

static inline int async_init();

// shuts down a socket
// use the posix style SHUT_RDWR, SHUT_RD, SHUT_WR
static inline void async_shutdown(async_t *a, int type);
static inline void async_close_socket(async_t *a);

// returns
// > 0 - number of bytes transferred
// 0 - transfer is pending
// < 0 - error

static inline int async_read(async_t *a, char *buf, int sz);
static inline int async_write(async_t *a, char *buf, int sz);
static inline int async_send_file(async_t *sock, async_t *file, char *hdr, int hdrsz, int64_t off, int filelen);

// returns
// >= 0 - number of bytes read
// or
#define ASYNC_ERROR -1
#define ASYNC_PENDING -2
#define ASYNC_NOT_MODIFIED -3

#define ASYNC_ACCEPT_BUFSZ (sizeof(struct sockaddr_storage) * 2)

static inline int async_accept(async_t *a, int family, async_t *child, char *buf, int bufsz);

// returns zero on success, non-zero on error
static inline int async_bind_udp(async_t *a, struct sockaddr *sa);
static inline int async_listen_tcp(async_t *a, struct sockaddr *sa);
static inline int async_listen_unix(async_t *a, const char *path);

// returns >= 0 - synchronous connect number of bytes sent
// ASYNC_PENDING or ASYNC_ERROR
static inline int async_connect(async_t *a, struct sockaddr *sa, char *msg, int mlen);

// returns 0 - success, non-zero - error
static inline int async_start_process(struct os_proc *proc, const char **argv, async_t *in, async_t *out);
static inline int async_open_process(struct os_proc *proc, const char *pidfile);
static inline void async_stop_process(struct os_proc *proc, int exit_code);

// if petag is non-null this will check for a change
// if no change it will return not ASYNC_NOT_MODIFIED
// if there is a change it will set the new etag in petag
// returns
// >= 0 - size of file
// or ASYNC_ERROR or ASYNC_NOT_MODIFIED

static inline int64_t async_open_file(async_t *a, const char *path, uint64_t *petag);
static inline void async_close_file(async_t *a);


struct free_list {
    struct free_list *next;
};
typedef void (*free_cb)(struct free_list *node);
typedef void (*async_cb)(async_t *a, int transferred);
typedef void (*accept_cb)(async_t *a, async_t *child, int transferred);
typedef void (*child_cb)(struct os_proc *proc, int pid, int exit_code);

// returns non-zero if the process should exit (-ve for error, +ve for clean exit)
//
// wait indicates the maximum time to wait for events
// the call will return on timeout or if any events are returned
//
// on_accept is called when async_accept finishes
// it returns the async_t of the new child
// transferred gives the number of bytes already read
// into the buffer provided to async_accept (which may be 0)
//
// readcb is called when async_read finishes
// transferred contains the number of bytes already read (which may be 0)
// transferred is -ve if an error or EOF occurred
//
// writecb is called when async_write or async_connect finishes
// transferred contains the number of bytes already written (which may be 0)
// transferred is -ve if on error, EOF, or the connect failed
//
// childcb is called when a child process exits (including if the user stopped
// it via async_stop). proc will point to the os_proc provided if the platform supports
// it, otherwise it will be NULL.
// pid is the child pid. exit_code contains the exit code.
//
// after calling the blocking poll function, pnow will be updated with the new
// monotonic time before calling any callbacks or returning
static inline int async_poll(os_duration_t wait, free_cb on_free, accept_cb on_accept, async_cb on_read, async_cb on_write, child_cb on_child, os_steady_t *pnow);

// register a free on node for the end of the next poll
// this will ensure that the callback is not called until
// after any events which may reference the node have been processed
static inline void async_free(struct free_list *node);

#define socksize(sa) ((sa)->sa_family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in))

#include <os/async/iocp.h>
#include <os/async/posix.h>

CEXTERN struct sockaddr_storage g_sockstorage;

static inline struct sockaddr* IPV4(uint32_t addr, uint16_t port) {
    struct sockaddr_in *sa = (struct sockaddr_in*) &g_sockstorage;
    sa->sin_family = AF_INET;
    sa->sin_port = ntohs(port);
    sa->sin_addr.s_addr = ntohl(addr);
    return (struct sockaddr*) sa;
}

static inline struct sockaddr* IPV6(const struct in6_addr *addr, uint16_t port) {
    struct sockaddr_in6 *sa = (struct sockaddr_in6*) &g_sockstorage;
    sa->sin6_family = AF_INET6;
    sa->sin6_port = ntohs(port);
    memcpy(&sa->sin6_addr.s6_addr, addr, sizeof(*addr));
    return (struct sockaddr*) sa;
}
