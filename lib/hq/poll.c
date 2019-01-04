#include "http.h"
#include <cutils/endian.h>
#include <cutils/char-array.h>
#include <cutils/timer.h>
#include <assert.h>
#include <limits.h>

struct hq_poll_socket {
	hq_continuation reader;
	hq_poll *poll;
	struct pollfd *pfd;
	const hq_source_class **source;
};

struct hq_poll_listen {
	struct hq_poll_socket hdr;
	const hq_listen_class *vtable;
};

struct hq_poll_connect {
	struct hq_poll_socket hdr;
	const hq_source_class *vtable;
	bool recv_fin;
	size_t rxbufsz, rxhave, rxused;
	char rxbuf[1];
};

tick_t get_tick() {
	return (tick_t)(monotonic_ns() / 1000);
}

static void add_socket(hq_poll *p, struct hq_poll_socket *s, int fd) {
	s->poll = p;
	s->pfd = &p->pfd[p->num];
	s->pfd->events = 0;
	s->pfd->fd = fd;
	p->sockets[p->num++] = s;
}

static void remove_socket(struct hq_poll_socket *s) {
	assert(!s->source);
	assert(!s->reader.fn);
	assert(s->pfd->fd >= 0);
	closesocket(s->pfd->fd);
	s->pfd->fd = (SOCKET)-1;
	s->pfd->events = 0;
	s->poll->dirty = true;
}

static void check_connected(struct hq_poll_connect *s) {
	if (!s->hdr.source && s->recv_fin && s->rxused == s->rxhave) {
		remove_socket(&s->hdr);
	}
}

static void do_abort(struct hq_poll_connect *s, int errnum) {
	assert(errnum < 0);
	hq_continue(&s->hdr.reader, errnum);
	hq_stop(&s->hdr.source, errnum);
	remove_socket(&s->hdr);
}

static void write_socket(struct hq_poll_connect *s);

static void source_has_data(void *user, int error) {
	struct hq_poll_connect *s = user;
	if (error) {
		do_abort(s, error);
	} else {
		write_socket(s);
	}
}

static void write_socket(struct hq_poll_connect *s) {
	const hq_source_class **src = s->hdr.source;
	s->hdr.pfd->events &= ~POLLOUT;
	for (;;) {
		const void *data;
		ssize_t r = (*src)->read(src, 0, 1, &data, &source_has_data, s);
		if (r == HQ_PENDING) {
			return;
		} else if (!r) {
			hq_stop(&s->hdr.source, 0);
			shutdown(s->hdr.pfd->fd, SHUT_WR);
			check_connected(s);
			return;
		} else if (r < 0) {
			do_abort(s, (int)r);
			return;
		}

		int w = send(s->hdr.pfd->fd, data, r > INT_MAX ? INT_MAX : (int)r, 0);
		if (w < 0 && would_block()) {
			s->hdr.pfd->events |= POLLOUT;
			return;
		} else if (w <= 0) {
			do_abort(s, HQ_ERR_TCP_RESET);
			return;
		}
		(*src)->seek(src, w);
	}
}

static ssize_t app_read(const hq_source_class **vt, size_t off, size_t minsz, const void **pdata, hq_continue_fn cb, void *user) {
	struct hq_poll_connect *s = container_of(vt, struct hq_poll_connect, vtable);

	if (s->rxused + minsz <= s->rxhave) {
		*pdata = s->rxbuf + s->rxused;
		return s->rxhave - s->rxused;
	}

	if (0 < s->rxused && s->rxused < s->rxhave) {
		s->rxhave -= s->rxused;
		memmove(s->rxbuf, s->rxbuf + s->rxused, s->rxhave);
	} else {
		s->rxhave = 0;
	}
	s->rxused = 0;

	int r = recv(s->hdr.pfd->fd, s->rxbuf + s->rxhave, (int)(s->rxbufsz - s->rxhave), 0);
	if (r < 0 && would_block()) {
		s->hdr.reader.fn = cb;
		s->hdr.reader.user = user;
		s->hdr.pfd->events |= POLLIN;
		return HQ_PENDING;
	} else if (r < 0) {
		do_abort(s, HQ_ERR_TCP_RESET);
		return HQ_ERR_TCP_RESET;
	}

	if (r == 0) {
		s->recv_fin = true;
	} else {
		s->rxhave += r;
	}

	*pdata = s->rxbuf;
	return s->rxhave;
}

static void app_stop(const hq_source_class **vt, int error) {
	struct hq_poll_connect *s = container_of(vt, struct hq_poll_connect, vtable);
	// even if we haven't seen a fin yet, pretend like we have
	// any remaining data can remain in the kernel buffer until we close the socket
	hq_cancel(&s->hdr.reader);
	s->hdr.pfd->events &= ~POLLIN;
	s->rxused = s->rxhave;
	s->recv_fin = true;
	check_connected(s);
}

static void app_seek(const hq_source_class **vt, size_t seek) {
	struct hq_poll_connect *s = container_of(vt, struct hq_poll_connect, vtable);
	hq_cancel(&s->hdr.reader);
	s->hdr.pfd->events &= ~POLLIN;
	s->rxused += seek;
#ifndef NDEBUG
	memset(s->rxbuf, 0xEE, s->rxused);
	assert(s->rxused <= s->rxhave);
#endif
	check_connected(s);
}

static const hq_source_class poll_socket_vtable = {
	&app_stop,
	&app_read,
	&app_seek,
};

static int poll_poll(const hq_poll_class **vt) {
	hq_poll *p = (hq_poll*)vt;

	int timeout = dispatch_apcs(&p->dispatcher, get_tick(), 1000);

	if (p->dirty) {
		size_t j = 0;
		for (size_t i = 0; i < p->num; i++) {
			if (p->pfd[i].fd < 0) {
				struct hq_poll_socket *s = p->sockets[i];
				p->pfd[j] = p->pfd[i];
				p->sockets[j] = s;
				s->pfd = &p->pfd[j];
				j++;
			}
		}
		p->num = j;
	}

	int err = poll(p->pfd, (int)p->num, timeout);
	if (err <= 0) {
		return err;
	}

	for (size_t i = 0; i < p->num; i++) {
		struct hq_poll_socket *s = p->sockets[i];
		struct pollfd *fd = &p->pfd[i];
		if (fd->fd > 0 && fd->revents && s) {
			if (fd->revents & POLLIN) {
				fd->events &= ~POLLIN;
				hq_continue(&s->reader, 0);
			}
			if (fd->revents & POLLOUT) {
				write_socket((struct hq_poll_connect*)s);
			}
			if (fd->revents & POLLERR) {
				hq_stop(&s->source, HQ_ERR_TCP_RESET);
				hq_continue(&s->reader, HQ_ERR_TCP_RESET);
			}
		}
	}

	return 0;
}

static int create_socket(int family, int type) {
#ifdef __linux__
	return socket(family, type, SOCK_CLOEXEC | SOCK_NONBLOCK);
#else
	int fd = (int)socket(family, type, 0);
	if (fd < 0 || set_non_blocking(fd) || set_cloexec(fd)) {
		closesocket(fd);
		return -1;
	}
	return fd;
#endif
}

static struct hq_poll_connect *init_connected(hq_poll *p, char *buf, size_t bufsz, const hq_source_class **src) {
	if (p->num == ARRAYSZ(p->sockets)) {
		return NULL;
	}

	char *start = (char*)ALIGN_UP((uintptr_t)buf, (uintptr_t)8);
	if (start + sizeof(struct hq_poll_socket) > buf + bufsz) {
		return NULL;
	}

	struct hq_poll_connect *s = (struct hq_poll_connect*)start;
	memset(s, 0, sizeof(*s));
	s->rxbufsz = (int)(buf + bufsz - s->rxbuf);
	s->vtable = &poll_socket_vtable;
	s->hdr.source = src;
	return s;
}

static const hq_source_class **poll_connect_tcp(const hq_poll_class **vt, char *buf, size_t bufsz, const struct sockaddr *sa, socklen_t len, const hq_source_class **source) {
	hq_poll *p = container_of(vt, hq_poll, vtable);
	struct hq_poll_connect *s = init_connected(p, buf, bufsz, source);
	if (!s) {
		return NULL;
	}

	int fd = create_socket(sa->sa_family, SOCK_STREAM);
	if (fd < 0) {
		return NULL;
	} else if (connect(fd, sa, len) && !would_block()) {
		closesocket(fd);
		return NULL;
	}

	add_socket(p, &s->hdr, fd);
	write_socket(s);
	return &s->vtable;
}

static void poll_close_listen(const hq_listen_class **vt) {
	struct hq_poll_listen *s = container_of(vt, struct hq_poll_listen, vtable);
	hq_cancel(&s->hdr.reader);
	remove_socket(&s->hdr);
}

static const hq_source_class **poll_accept_tcp(const hq_listen_class **vt, char *buf, size_t bufsz, struct sockaddr *remote, socklen_t *salen, const hq_source_class **source, hq_continue_fn cb, void *user) {
	struct hq_poll_listen *ln = container_of(vt, struct hq_poll_listen, vtable);
	hq_poll *p = ln->hdr.poll;

#ifdef __linux__
	int fd = accept4(ln->hdr.pfd->fd, remote, salen, SOCK_CLOEXEC | SOCK_NONBLOCK);
#else
	int fd = (int)accept(ln->hdr.pfd->fd, remote, salen);
#endif

	if (fd < 0 && would_block()) {
		ln->hdr.pfd->events |= POLLIN;
		ln->hdr.reader.fn = cb;
		ln->hdr.reader.user = user;
		return NULL;
	}

#ifndef __linux__
	if (set_non_blocking(fd) || set_cloexec(fd)) {
		closesocket(fd);
		return NULL;
	}
#endif

	struct hq_poll_connect *s = init_connected(p, buf, bufsz, source);
	if (!s) {
		return NULL;
	}
	add_socket(p, &s->hdr, fd);
	write_socket(s);
	return &s->vtable;
}

static const hq_listen_class poll_listen_vtable = {
	&poll_close_listen,
	&poll_accept_tcp,
};

static const hq_listen_class **poll_listen_tcp(const hq_poll_class **vt, char *buf, size_t bufsz, const struct sockaddr *sa, socklen_t len) {
	hq_poll *p = container_of(vt, hq_poll, vtable);
	if (p->num == ARRAYSZ(p->sockets)) {
		return NULL;
	}

	char *start = (char*)ALIGN_UP((uintptr_t)buf, (uintptr_t)8);
	if (start + sizeof(struct hq_poll_listen) > buf + bufsz) {
		return NULL;
	}

	struct hq_poll_listen *s = (struct hq_poll_listen*)start;
	memset(s, 0, sizeof(*s));
	s->vtable = &poll_listen_vtable;

	int fd = create_socket(sa->sa_family, SOCK_STREAM);
	if (fd < 0) {
		return NULL;
	} else if (bind(fd, sa, len) || listen(fd, SOMAXCONN)) {
		closesocket(fd);
		return NULL;
	}

	add_socket(p, &s->hdr, fd);
	return &s->vtable;
}

const hq_poll_class async_poll_vtable = {
	&poll_poll,
	&poll_connect_tcp,
	&poll_listen_tcp,
};

void hq_init_poll(hq_poll *p) {
#ifdef WIN32
	WSADATA wsa;
	WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
	p->vtable = &async_poll_vtable;
	p->num = 0;
	init_dispatcher(&p->dispatcher, get_tick());
}

