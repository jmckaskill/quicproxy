#include "http.h"
#include <cutils/endian.h>
#include <cutils/char-array.h>
#include <assert.h>
#include <limits.h>

struct hq_poll_socket {
	const hq_stream_class *vtable;
	const hq_stream_class **source;
	const hq_stream_class **read_cb;
	hq_free_cb free;
	void *free_user;
	hq_poll *poll;
	struct pollfd *pfd;
	bool *pdirty;
	int fd;
	bool recv_finished;
	bool recv_ignore;
	bool send_finished;
	int rxbufsz, rxhave, rxused;
	char rxbuf[1];
};

static void remove_socket(struct hq_poll_socket *s, int errnum) {
	assert(s->fd >= 0);
	closesocket(s->fd);
	s->pfd->fd = (SOCKET)-1;
	s->pfd->events = 0;
	*s->pdirty = true;
	if (s->free) {
		s->free(s->free_user);
	}
}

static void check_socket(struct hq_poll_socket *s) {
	if (s->recv_finished && s->send_finished && !s->rxhave) {
		assert(!s->source && !s->read_cb);
		remove_socket(s, 0);
	}
}

static void do_abort(struct hq_poll_socket *s, int errnum) {
	assert(errnum);
	if (s->read_cb) {
		(*s->read_cb)->read_finished(s->read_cb, NULL, errnum);
		s->read_cb = NULL;
	}
	if (s->source) {
		(*s->source)->finish_read(s->source, errnum);
		s->source = NULL;
	}
	remove_socket(s, errnum);
}

static void write_socket(struct hq_poll_socket *s) {
	for (;;) {
		// source can change from one loop to the next
		const hq_stream_class **src = s->source;
		if (!src) {
			return;
		}

		const void *data;
		int r = (*src)->start_read(src, &s->vtable, 1, &data);
		if (r == HQ_PENDING) {
			return;
		} else if (!r) {
			s->send_finished = true;
			s->source = NULL;
			shutdown(s->fd, SHUT_WR);
			check_socket(s);
			return;
		} else if (r < 0) {
			s->source = NULL;
			do_abort(s, r);
			return;
		}

		int w = send(s->fd, data, r, 0);
		if (w < 0 && would_block()) {
			s->pfd->events |= POLLOUT;
			return;
		} else if (w <= 0) {
			do_abort(s, HQ_ERR_TCP_RESET);
			return;
		}
		(*s->source)->finish_read(s->source, w);
	}
}

static int app_start_read(const hq_stream_class **vt, const hq_stream_class **sink, int minsz, const void **pdata) {
	struct hq_poll_socket *s = (struct hq_poll_socket*)vt;
	assert(!s->read_cb);

	if (s->rxused + minsz <= s->rxhave) {
		*pdata = s->rxbuf + s->rxused;
		return s->rxhave - s->rxused;
	}

	if (0 < s->rxused && s->rxused < s->rxhave) {
		s->rxhave -= s->rxused;
		memmove(s->rxbuf, s->rxbuf + s->rxused, s->rxhave);
		s->rxused = 0;
	}

	int r = recv(s->fd, s->rxbuf + s->rxhave, s->rxbufsz - s->rxhave, 0);
	if (r < 0 && would_block()) {
		s->pfd->events |= POLLIN;
		s->read_cb = sink;
		return HQ_PENDING;
	} else if (r < 0) {
		do_abort(s, HQ_ERR_TCP_RESET);
		return HQ_ERR_TCP_RESET;
	}

	*pdata = s->rxbuf;

	if (r == 0) {
		s->recv_finished = true;
		return s->rxhave;
	} else if (!s->recv_ignore) {
		s->rxhave += r;
		return s->rxhave;
	} else {
		return HQ_PENDING;
	}
}

static void app_finish_read(const hq_stream_class **vt, int finished) {
	struct hq_poll_socket *s = (struct hq_poll_socket*)vt;
	s->read_cb = NULL;
	s->pfd->events &= ~POLLIN;
	if (finished < 0) {
		s->rxhave = 0;
		s->rxused = 0;
		s->recv_ignore = true;
	} else {
		s->rxused += finished;
		assert(s->rxused <= s->rxhave);
	}
	check_socket(s);
}

static void app_read_finished(const hq_stream_class **vt, const hq_stream_class **source, int error) {
	struct hq_poll_socket *s = (struct hq_poll_socket*)vt;
	s->source = source;
	if (error) {
		do_abort(s, error);
	} else if (source && !(s->pfd->events & POLLOUT)) {
		write_socket(s);
	}
}

static const hq_stream_class poll_socket_vtable = {
	&app_start_read,
	&app_finish_read,
	&app_read_finished,
};

static int poll_poll(const hq_poll_class **vt, dispatcher_t *d, tick_t now) {
	hq_poll *p = (hq_poll*)vt;

	int timeout = -1;
	if (d) {
		timeout = dispatch_apcs(d, now, 1000);
	}

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
			if (fd->revents & POLLOUT) {
				fd->events &= ~POLLOUT;
				write_socket(s);
			}
			if (fd->revents & POLLIN) {
				fd->events &= ~POLLIN;
				const hq_stream_class **cb = s->read_cb;
				if (cb) {
					s->read_cb = NULL;
					(*cb)->read_finished(cb, &s->vtable, 0);
				} else if (s->recv_ignore) {
					const void *data;
					if (app_start_read(&s->vtable, NULL, 1, &data) == 0) {
						check_socket(s);
					}
				}
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
	s->rxbufsz = (int)(rxbuf + bufsz - s->rxbuf);
	s->vtable = &poll_socket_vtable;
	s->pfd = &p->pfd[p->num];
	
	s->fd = create_socket(sa->sa_family, SOCK_STREAM);
	if (s->fd < 0) {
		goto err;
	} else if (connect(s->fd, sa, len) < 0 && !would_block()) {
		goto err;
	}

	p->pfd[p->num].events = POLLOUT;
	p->pfd[p->num].fd = s->fd;
	p->sockets[p->num++] = s;
	return &s->vtable;

err:
	closesocket(s->fd);
	if (free) {
		free(user);
	}
	return NULL;
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

