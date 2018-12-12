#pragma once
#ifndef WIN32

#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <spawn.h>
#include <sys/stat.h>
#include <poll.h>
#include <string.h>

#include "epoll.h"
#include "kqueue.h"

#ifdef __linux__
#include <sys/sendfile.h>
#else
#define SOCK_NONBLOCK 1
#define SOCK_CLOEXEC 2
static inline int non_linux_accept4(int lfd, struct sockaddr *sa, socklen_t *sasz, int flags) {
	int fd = accept(lfd, sa, sasz);
	if (fd < 0) {
		return -1;
	}
	if (flags & SOCK_NONBLOCK) {
		fcntl(fd, F_SETFL, O_NONBLOCK);
	}
	if (flags & SOCK_CLOEXEC) {
		fcntl(fd, F_SETFD, FD_CLOEXEC);
	}
	return fd;
}
#define accept4 non_linux_accept4
#endif

static inline void async_shutdown(async_t *a, int type) {
	shutdown(a->fd, type);
}

static inline void async_close_socket(async_t *a) {
	close(a->fd);
}

// EINTR loops are not required because all calls are non-blocking

static inline int async_read(async_t *a, char *buf, int sz) {
	int r = read(a->fd, buf, sz);

	if (r > 0) {
		return r;
	} else if (r == 0) {
		return ASYNC_ERROR;
	} else if (errno == EAGAIN) {
		a->events |= ASYNC_FLAG_READ;
		return 0;
	} else {
		return ASYNC_ERROR;
	}
}

static inline int async_write(async_t *a, char *buf, int sz) {
	int r = write(a->fd, buf, sz);

	if (r > 0) {
		return r;
	} else if (r == 0) {
		return ASYNC_ERROR;
	} else if (errno == EAGAIN) {
		a->events |= ASYNC_FLAG_WRITE;
		return 0;
	} else {
		return ASYNC_ERROR;
	}
}

static inline int async_send_file(async_t *sock, async_t *file, char *hdr, int hdrsz, int64_t off, int filelen) {
	assert(filelen > 0);
	debug("sendfile %d %d", hdrsz, filelen);
#ifdef __linux__
	if (hdrsz) {
		return async_write(sock, hdr, hdrsz);
	}

	int r = sendfile(sock->fd, file->fd, &off, filelen);

	if (r > 0) {
		return r;
	} else if (errno == EAGAIN) {
		sock->events |= ASYNC_FLAG_WRITE;
		return 0;
	} else {
		return ASYNC_ERROR;
	}

#else
	// BSD style
	struct iovec iov = {hdr, hdrsz};
	struct sf_hdtr fb = {&iov, 1, NULL, 0};
	off_t written = filelen;
	int r = sendfile(file->fd, sock->fd, off, &written, &fb, 0);

	if (r && errno == EAGAIN) {
		return 0;
	} else if (!r && written > 0) {
		return (int) written;
	} else {
		return ASYNC_ERROR;
	}
#endif
}

static inline int async_accept(async_t *a, int family, async_t *child, char *buf, int bufsz) {
	a->accept = child;
	child->events = 0;
	child->accept = NULL;
	child->fd = accept4(a->fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);

	if (child->fd >= 0) {
		watch_both(child);
		return 0;
	} else if (errno == EAGAIN) {
		a->events |= ASYNC_FLAG_READ;
		return ASYNC_PENDING;
	} else {
		return ASYNC_ERROR;
	}
}

static inline int async_bind_udp(async_t *a, struct sockaddr *sa) {
	int fd = socket(sa->sa_family, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		syserror("create listening socket");
		return -1;
	}

	int on = 1;
	if (sa->sa_family == AF_INET6 && setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on))) {
		syserror("set v6 only");
		close(fd);
		return -1;
	}
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) {
		syserror("reuse address");
		close(fd);
		return -1;
	}

	if (bind(fd, sa, socksize(sa))) {
		syserror("bind");
		close(fd);
		return -1;
	}

	if (fcntl(fd, F_SETFD, FD_CLOEXEC) || fcntl(fd, F_SETFL, O_NONBLOCK)) {
		syserror("fcntl");
		close(fd);
		return -1;
	}

	a->events = 0;
	a->fd = fd;
	a->accept = NULL;
	watch_read(a);

	return 0;
}

static inline int async_listen_unix(async_t *a, const char *fn) {
    struct sockaddr_un sun = {0};
    sun.sun_family = AF_UNIX;
    strncpy(sun.sun_path, fn, sizeof(sun.sun_path));

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);

    if (fcntl(fd, F_SETFL, O_NONBLOCK)
	|| fcntl(fd, F_SETFD, FD_CLOEXEC)
    || bind(fd, (struct sockaddr*) &sun, sizeof(sun)) 
    || listen(fd, SOMAXCONN)) {
        perror("failed to bind unix socket");
		return -1;
    }
	
	a->events = 0;
	a->fd = fd;
	a->accept = NULL;
	watch_read(a);

	return 0;
}

static inline int async_listen_tcp(async_t *a, struct sockaddr *sa) {
	int fd = socket(sa->sa_family, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		syserror("create listening socket");
		return -1;
	}

	int on = 1;
	if (sa->sa_family == AF_INET6 && setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on))) {
		syserror("set v6 only");
		close(fd);
		return -1;
	}
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) {
		syserror("reuse address");
		close(fd);
		return -1;
	}
	if (fcntl(fd, F_SETFD, FD_CLOEXEC) || fcntl(fd, F_SETFL, O_NONBLOCK)) {
		syserror("fcntl listen fd");
		close(fd);
		return -1;
	}
	if (bind(fd, sa, socksize(sa)) || listen(fd, SOMAXCONN)) {
		syserror("bind");
		close(fd);
		return -1;
	}

	a->events = 0;
	a->fd = fd;
	a->accept = NULL;
	watch_read(a);

	return 0;
}

static void async_stop_process(struct os_proc *proc, int exit_code) {
	// always kill the group even when the process exited so that we kill
	// all the other processes in the group
	proc_kill_group(proc, exit_code);
	// the main loop waits for SIGCHLD to know that the process has indeed exited
}

static inline int async_open_process(struct os_proc *proc, const char *pidfile) {
	// if the process is not a child process, getting notifications when it stops
	// is hard. this is possible with kqueue, but there's limited value implementing it
	return proc_open_pidfile(proc, pidfile);
}

static inline int async_start_process(struct os_proc *proc, const char **argv, async_t *in, async_t *out) {
	int to[2] = {-1,-1};
	int from[2] = {-1,-1};

	if (pipe(to) || pipe(from)) {
		goto err;
	}
	if (fcntl(to[1], F_SETFD, FD_CLOEXEC) || fcntl(from[0], F_SETFD, FD_CLOEXEC)) {
		goto err;
	}
	if (fcntl(to[1], F_SETFL, O_NONBLOCK) || fcntl(from[0], F_SETFL, O_NONBLOCK)) {
		goto err;
	}

	in->fd = to[1];
	out->fd = from[0];

	in->accept = NULL;
	out->accept = NULL;

	in->events = 0;
	out->events = 0;

	watch_write(in);
	watch_read(out);

	proc->in = to[0];
	proc->out = from[1];
	proc->err = pipe_stderr();

	if (proc_start(proc, argv, PROC_NEW_GROUP)) {
		syserror("proc_start");
		goto err;
	}

	close(to[0]);
	close(from[1]);

	return 0;

err:
	close(to[0]);
	close(to[1]);
	close(from[0]);
	close(from[1]);
	return -1;
}

static inline int async_connect(async_t *a, struct sockaddr *sa, char *msg, int mlen) {
	int fd = socket(sa->sa_family, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		syserror("create backend socket");
		return ASYNC_ERROR;
	}

	if (fcntl(fd, F_SETFD, FD_CLOEXEC) || fcntl(fd, F_SETFL, O_NONBLOCK)) {
		syserror("fcntl backend");
		close(fd);
		return ASYNC_ERROR;
	}

	a->events = 0;
	a->fd = fd;
	a->accept = NULL;
	watch_both(a);

	if (!connect(fd, sa, socksize(sa))) {
		// success
	} else if (errno == EINPROGRESS) {
		a->events |= ASYNC_FLAG_WRITE;
		return ASYNC_PENDING;
	} else {
		syserror("connect to backend");
		close(fd);
		return ASYNC_ERROR;
	}

	int r = async_write(a, msg, mlen);
	if (r < 0) {
		syserror("initial send to backend");
		close(fd);
	}
	
	return r;
}

static inline int64_t async_open_file(async_t *a, const char *path, uint64_t *petag) {
	// on posix regular files are always blocking, so no need for O_NONBLOCK or setting
	// up the watcher
	int fd = open(path, O_CLOEXEC | O_RDONLY);
	if (fd < 0) {
		return ASYNC_ERROR;
	}

	struct stat st;
	if (fstat(fd, &st)) {
		syserror("fstat");
		close(fd);
		return ASYNC_ERROR;
	}

	if (petag) {
		uint32_t sz = (uint64_t) st.st_size;
		uint32_t tm = (uint32_t) st.st_mtime;
		uint64_t etag = (((uint64_t) sz) << 32) | (uint64_t)tm;

		if (etag == *petag) {
			close(fd);
			return ASYNC_NOT_MODIFIED;
		}
		*petag = etag;
	}

	a->fd = fd;
	return (int64_t) st.st_size;
}

static inline void async_close_file(async_t *a) {
	close(a->fd);
}

static inline void async_free(struct free_list *udata) {
	udata->next = g_to_free;
	g_to_free = udata;
}

#endif
