#include <cutils/poll.h>
#include <cutils/char-array.h>
#include <assert.h>
#include <limits.h>

#define IS_STREAM 1
#define IS_CONNECTED 2

static int poll_poll(const async_class **vt, int timeout) {
	async_poll *a = (async_poll*)vt;

	if (a->have_close) {
		// compact the fd array
		size_t to = 0;
		for (size_t from = 0; from < a->num; from++) {
			if (a->sockets[from]) {
				a->sockets[from]->idx = to;
				a->sockets[to] = a->sockets[from];
				memcpy(&a->pfd[to], &a->pfd[from], sizeof(a->pfd[from]));
				to++;
			}
		}
		a->num = to;
		a->have_close = false;
	}

	int err = poll(a->pfd, (int)a->num, timeout);
	if (err <= 0) {
		return err;
	}

	for (size_t i = 0; i < a->num; i++) {
		struct pollfd *p = &a->pfd[i];
		if (p->fd > 0 && p->revents && a->sockets[i]) {
			a->sockets[i]->flags |= IS_CONNECTED;
			p->events &= ~(p->revents & (POLLIN | POLLOUT));
			a->sockets[i]->cb(a->sockets[i], p->revents);
		}
	}
	return 0;
}

static void poll_close(const async_class **vt, async_socket *s) {
	async_poll *a = (async_poll*)vt;
	size_t i = s->idx;
	assert(i < a->num && a->sockets[i] == s);
	closesocket(s->fd);
	a->sockets[i] = NULL;
	a->have_close = true;
}

static void poll_cancel(const async_class **vt, async_socket *s) {
	(void)vt;
	(void)s;
}

static int add_socket(async_poll *a, async_socket *s, async_socket_cb cb) {
	if (a->num == ARRAYSZ(a->pfd)) {
		return ASYNC_TOOMANY;
	} else if (set_non_blocking(s->fd) || set_cloexec(s->fd)) {
		return ASYNC_SYSERROR;
	}
	size_t i = a->num++;
	a->sockets[i] = s;
	a->pfd[i].events = 0;
	a->pfd[i].fd = s->fd;
	s->cb = cb;
	s->idx = i;
	return 0;
}

static int poll_new_socket(const async_class **vt, async_socket *s, int family, int type, int protocol, async_socket_cb cb) {
	async_poll *a = (async_poll*)vt;
	int fd = (int)socket(family, type, protocol);
	if (fd < 0) {
		return ASYNC_SYSERROR;
	}
	memset(s, 0, sizeof(*s));
	s->fd = fd;
	s->flags = (type == SOCK_STREAM) ? IS_STREAM : 0;
	return add_socket(a, s, cb);
}

static int poll_add_listener(const async_class **vt, async_listener *ln, int fd, async_listen_cb cb) {
	async_poll *a = (async_poll*)vt;
	if (a->num == ARRAYSZ(a->pfd)) {
		return ASYNC_TOOMANY;
	} else if (set_non_blocking(fd) || set_cloexec(fd)) {
		return ASYNC_SYSERROR;
	}
	size_t i = a->num++;
	a->sockets[i] = (async_socket*)ln;
	a->pfd[i].events = POLLERR;
	a->pfd[i].fd = fd;
	memset(ln, 0, sizeof(*ln));
	ln->cb = cb;
	ln->fd = fd;
	ln->idx = i;
	return 0;
}

static ssize_t poll_connect(const async_class **vt, async_socket *s, const struct sockaddr *sa, socklen_t len, const char *initial_msg, size_t mlen) {
	async_poll *a = (async_poll*)vt;
	size_t i = s->idx;
	assert(i < a->num && a->sockets[i] == s);
	memcpy(&s->buf[0], sa, len);
	s->local = (struct sockaddr*) &s->buf[0];
	s->local_len = len;
	int err = connect(s->fd, s->local, s->local_len);
	if (err < 0 && would_block()) {
		a->pfd[i].events |= POLLOUT;
		return ASYNC_PENDING;
	} else if (err < 0) {
		return ASYNC_SYSERROR;
	} else {
		return 0;
	}
}

static ssize_t poll_read(const async_class **vt, async_socket *s, char *buf, size_t len) {
	async_poll *a = (async_poll*)vt;
	size_t i = s->idx;
	assert(i < a->num && a->sockets[i] == s);
	int r = recvfrom(s->fd, buf, len > INT_MAX ? INT_MAX : (int)len, 0, s->remote, &s->remote_len);
	if (r < 0 && would_block()) {
		a->pfd[i].events |= POLLIN;
		return ASYNC_PENDING;
	} else if (r < 0) {
		return ASYNC_SYSERROR;
	} else {
		return r;
	}
}

static ssize_t poll_write(const async_class **vt, async_socket *s, const char *buf, size_t len, const struct sockaddr *sa, socklen_t salen) {
	async_poll *a = (async_poll*)vt;
	size_t i = s->idx;
	assert(i < a->num && a->sockets[i] == s);
	if ((s->flags & IS_STREAM) && !(s->flags & IS_CONNECTED)) {
		int c = connect(s->fd, sa, salen);
		if (c < 0 && would_block()) {
			a->pfd[i].events |= POLLOUT;
			return ASYNC_PENDING;
		} else if (c < 0) {
			return ASYNC_SYSERROR;
		}
		s->flags |= IS_CONNECTED;
	}
	int r = send(s->fd, buf, len > INT_MAX ? INT_MAX : (int)len, 0);
	if (r < 0 && would_block()) {
		a->pfd[i].events |= POLLOUT;
		return ASYNC_PENDING;
	} else if (r < 0) {
		return ASYNC_SYSERROR;
	} else {
		return r;
	}
}

static int poll_accept(const async_class **vt, async_listener *ln, async_socket *s, char *buf, size_t len, async_socket_cb cb) {
	async_poll *a = (async_poll*)vt;
	size_t i = s->idx;
	assert(i < a->num && a->sockets[i] == (async_socket*)ln);
	if (a->num == ARRAYSZ(a->pfd)) {
		return ASYNC_TOOMANY;
	}
	ln->accepted = false;
	ln->sock = s;
	s->remote_len = sizeof(s->buf[1]);
	s->remote = (struct sockaddr*)&s->buf[1];
#ifdef __linux__
	int fd = accept4(ln->fd, s->remote, &s->remote_len, SOCK_NONBLOCK | SOCK_CLOEXEC);
#else
	int fd = (int)accept(ln->fd, s->remote, &s->remote_len);
#endif
	if (fd < 0 && would_block()) {
		a->pfd[i].events |= POLLIN;
		return ASYNC_PENDING;
	} else if (fd < 0) {
		return ASYNC_SYSERROR;
	}
	return poll_add_socket(vt, s, fd, cb);
}

const async_class async_poll_vtable = {
	1000000,
	&poll_poll,
	&poll_close,
	&poll_cancel,
	&poll_add_socket,
	&poll_add_listener,
	&poll_connect,
	&poll_read,
	&poll_write,
	NULL,
	&poll_accept,
};

void async_init_poll(async_poll *a) {
#ifdef WIN32
	WSADATA wsa;
	WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
	a->vtable = &async_poll_vtable;
	a->num = 0;
	a->have_close = false;
}

