#include "http.h"
#include <cutils/endian.h>
#include <cutils/char-array.h>
#include <assert.h>
#include <limits.h>

struct hq_poll_socket {
	const hq_stream_class *vtable;
	const hq_stream_class **source, **sink;
	hq_free_cb free;
	void *free_user;
	hq_poll *poll;
	struct pollfd *pfd;
	bool *pdirty;
	int fd;
	bool recv_finished;
	bool recv_ignore;
	bool send_finished;
	size_t bufsz, start, next;
	char buf[1];
};

static void remove_socket(struct hq_poll_socket *s, int errnum) {
	if (s->source) {
		(*s->source)->close(s->source, errnum);
	}
	assert(s->fd >= 0);
	closesocket(s->fd);
	s->source = NULL;
	s->sink = NULL;
	s->fd = -1;
	s->pfd->fd = (SOCKET)-1;
	s->pfd->events = 0;
	*s->pdirty = true;
}

static void check_socket(struct hq_poll_socket *s) {
	if (s->recv_finished && s->send_finished && s->start == s->next) {
		remove_socket(s, HQ_ERR_SUCCESS);
	}
}

static void do_abort(struct hq_poll_socket *s, int errnum) {
	if (s->sink) {
		(*s->sink)->abort(s->sink, errnum);
		s->sink = NULL;
	}
	remove_socket(s, errnum);
}

static void write_socket(struct hq_poll_socket *s) {
	s->pfd->events &= ~POLLOUT;
	for (;;) {
		// source can change from one loop to the next
		const hq_stream_class **src = s->source;
		if (!src) {
			return;
		}

		const void *data;
		ssize_t sz = (*src)->peek(src, 0, &data);
		if (sz == HQ_PENDING) {
			return;
		} else if (!sz) {
			s->send_finished = true;
			s->source = NULL;
			shutdown(s->fd, SHUT_WR);
			check_socket(s);
			return;
		} else if (sz < 0) {
			do_abort(s, -(int)sz);
			return;
		}

		int w = send(s->fd, data, sz > INT_MAX ? INT_MAX : (int)sz, 0);
		if (w < 0 && would_block()) {
			s->pfd->events |= POLLOUT;
			return;
		} else if (w <= 0) {
			do_abort(s, HQ_ERR_TCP_RESET);
			return;
		}
		(*s->source)->seek(s->source, (size_t)w);
	}
}

static void read_socket(struct hq_poll_socket *s) {
	bool recvd_any = false;
	for (;;) {
		size_t toread = (s->start + s->bufsz - 1 - s->next) % s->bufsz;
		if (!toread) {
			s->pfd->events &= ~POLLIN;
			break;
		}
		int r = recv(s->fd, s->buf + s->next, toread > INT_MAX ? INT_MAX : (int)toread, 0);
		if (r < 0 && would_block()) {
			return;
		} else if (r < 0) {
			do_abort(s, HQ_ERR_TCP_RESET);
			return;
		} else if (r == 0) {
			recvd_any = true;
			s->recv_finished = true;
			break;
		}
		if (!s->recv_ignore) {
			recvd_any = true;
			s->next = (s->next + r) % s->bufsz;
		}
	}

	if (recvd_any && s->sink) {
		(*s->sink)->notify(s->sink);
		check_socket(s);
	}
}

static void set_source(const hq_stream_class **vt, const hq_stream_class **source) {
	struct hq_poll_socket *s = (struct hq_poll_socket*)vt;
	s->source = source;
	if (source && !(s->pfd->events & POLLOUT)) {
		write_socket(s);
	}
}

static void set_sink(const hq_stream_class **vt, const hq_stream_class **sink) {
	struct hq_poll_socket *s = (struct hq_poll_socket*)vt;
	s->sink = sink;
}

static ssize_t peek_socket(const hq_stream_class **vt, size_t off, const void **pdata) {
	struct hq_poll_socket *s = (struct hq_poll_socket*)vt;
	size_t have = (s->next - s->start) % s->bufsz;
	assert(off <= have);
	if (off >= have) {
		return s->recv_finished ? 0 : HQ_PENDING;
	}
	size_t start = (s->start + off) % s->bufsz;
	size_t end = start + have;

	*pdata = s->buf + start;
	return (end > s->bufsz) ? (s->bufsz - start) : have;
}

static void seek_socket(const hq_stream_class **vt, size_t sz) {
	struct hq_poll_socket *s = (struct hq_poll_socket*)vt;
	assert(sz <= ((s->next - s->start) % s->bufsz));
	s->start = (s->start + sz) % s->bufsz;
	if (!s->recv_finished) {
		s->pfd->events |= POLLIN;
	}
}

static void close_socket(const hq_stream_class **vt, int errnum) {
	struct hq_poll_socket *s = (struct hq_poll_socket*)vt;
	s->recv_ignore = true;
	s->start = 0;
	s->next = 0;
}

static void abort_socket(const hq_stream_class **vt, int errnum) {
	struct hq_poll_socket *s = (struct hq_poll_socket*)vt;
	s->source = NULL;
	do_abort(s, errnum);
}

static void notify_socket(const hq_stream_class **vt) {
	struct hq_poll_socket *s = (struct hq_poll_socket*)vt;
	if (s->pfd->events & POLLOUT) {
		write_socket(s);
	}
}

static const hq_stream_class poll_socket_vtable = {
	&set_sink,
	&peek_socket,
	&seek_socket,
	&close_socket,
	&set_source,
	&abort_socket,
	&notify_socket,
};

static int poll_poll(const hq_poll_class **vt, dispatcher_t *d, tick_t now) {
	hq_poll *p = (hq_poll*)vt;

	int timeout = -1;
	if (d) {
		timeout = dispatch_apcs(d, now, 1000);
	}

	if (p->dirty) {
		for (size_t i = 0, j = 0; i < p->num; i++) {
			if (p->pfd[i].fd < 0) {
				struct hq_poll_socket *s = p->sockets[i];
				p->pfd[j] = p->pfd[i];
				p->sockets[j] = s;
				s->pfd = &p->pfd[j];
				j++;
			}
		}
	}

	int err = poll(p->pfd, (int)p->num, timeout);
	if (err <= 0) {
		return err;
	}

	for (size_t i = 0; i < p->num; i++) {
		struct hq_poll_socket *s = p->sockets[i];
		struct pollfd *fd = &p->pfd[i];
		if (fd->fd > 0 && fd->revents && s) {
			if (fd->revents & POLLOUT) {
				write_socket(s);
			}
			if (fd->revents & POLLIN) {
				read_socket(s);
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

static const hq_stream_class **poll_new_connection(const hq_poll_class **vt, const struct sockaddr *sa, socklen_t len, char *rxbuf, size_t bufsz, hq_free_cb free, void *user) {
	hq_poll *p = (hq_poll*)vt;
	if (p->num == ARRAYSZ(p->sockets)) {
		return NULL;
	}
	char *start = (char*)ALIGN_UP((uintptr_t)rxbuf, (uintptr_t)8);
	if (start + sizeof(struct hq_poll_socket) > rxbuf + bufsz) {
		return NULL;
	}
	struct hq_poll_socket *s = (struct hq_poll_socket*)start;
	memset(s, 0, sizeof(*s));
	s->bufsz = rxbuf + bufsz - s->buf;
	s->vtable = &poll_socket_vtable;
	s->pfd = &p->pfd[p->num];
	
	s->fd = create_socket(sa->sa_family, SOCK_STREAM);
	if (s->fd < 0) {
		return NULL;
	} else if (connect(s->fd, sa, len) < 0 && !would_block()) {
		closesocket(s->fd);
		return NULL;
	}

	p->pfd[p->num].events = POLLIN | POLLOUT;
	p->pfd[p->num].fd = s->fd;
	p->sockets[p->num++] = s;
	return &s->vtable;
}

const hq_poll_class async_poll_vtable = {
	&poll_poll,
	&poll_new_connection,
};

void hq_init_poll(hq_poll *p) {
#ifdef WIN32
	WSADATA wsa;
	WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
	p->vtable = &async_poll_vtable;
	p->num = 0;
}

