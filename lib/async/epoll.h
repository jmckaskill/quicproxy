#pragma once
#ifdef __linux__
#include <sys/epoll.h>

//#define HAVE_SPLICE

struct async {
	// user setable
	void *udata;
	int fd;
	// internal
	async_t *accept;
	int events;
};

#define ASYNC_FLAG_READ (EPOLLIN|EPOLLHUP)
#define ASYNC_FLAG_WRITE EPOLLOUT

CEXTERN int g_epoll;
CEXTERN sigset_t g_onagain;
CEXTERN int g_have_sigchld;
CEXTERN int g_have_sigterm;
CEXTERN struct free_list *g_to_free;

CFUNC void on_sigchld(int sig);
CFUNC void on_sigterm(int sig);

static inline int async_init() {
	assert(!g_epoll);
	g_epoll = epoll_create1(EPOLL_CLOEXEC);
	if (g_epoll < 0) {
		syserror("epoll init");
		return -1;
	}

	sigset_t off;
	sigemptyset(&g_onagain);
	sigemptyset(&off);
	sigaddset(&off, SIGCHLD);
	sigaddset(&off, SIGTERM);

	if (pthread_sigmask(SIG_SETMASK, &off, NULL) 
	|| signal(SIGCHLD, &on_sigchld) == SIG_ERR
	|| signal(SIGTERM, &on_sigterm) == SIG_ERR
	|| signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		perror("setup signals");
		return -1;
	}

	return 0;
}

static inline void do_watch(async_t *a, int events) {
    struct epoll_event ev = {events, {a}};
	if (epoll_ctl(g_epoll, EPOLL_CTL_ADD, a->fd, &ev)) {
		syserror("epoll ctl");
	}
}

static inline void watch_read(async_t *a) {
    do_watch(a, EPOLLIN|EPOLLET);
}

static inline void watch_write(async_t *a) {
    do_watch(a, EPOLLOUT|EPOLLET);
}

static inline void watch_both(async_t *a) {
    do_watch(a, EPOLLIN|EPOLLOUT|EPOLLET);
}

static inline int async_poll(os_duration_t wait, free_cb on_free, accept_cb on_accept, async_cb on_read, async_cb on_write, child_cb on_child, os_steady_t *pnow) {
	struct epoll_event ev[64];
	int timeout = (wait == OS_TIME_MAX) ? -1 : (int) to_ms(wait);
	int num = epoll_pwait(g_epoll, ev, 64, timeout, &g_onagain);

	if (num < 0 && errno != EINTR) {
		return -1;
	} else if (g_have_sigterm) {
		return 1;
	}

	*pnow = os_steady();

	if (on_child && g_have_sigchld) {
		g_have_sigchld = 0;
		int pid, sts;
		while ((pid = waitpid(-1, &sts, WNOHANG)) > 0) {
			on_child(NULL, pid, sts);
		}
	}

	for (int i = 0; i < num; i++) {
		async_t *a = (async_t*) ev[i].data.ptr;
		if (ev[i].events & (EPOLLIN | EPOLLHUP) & a->events) {
			a->events &= ~ASYNC_FLAG_READ;
			if (a->accept) {
				assert(on_accept != NULL);
				// buf, bufsz, and family are not used by the posix async_accept
				if (async_accept(a, 0, a->accept, NULL, 0) >= 0) {
					on_accept(a, a->accept, 0);
				}
			} else if (on_read) {
				on_read(a, 0);
			}
		}

		if (on_write && (ev[i].events & EPOLLOUT & a->events)) {
			a->events &= ~ASYNC_FLAG_WRITE;
			on_write(a, 0);
		}
	}

	if (on_free) {
		struct free_list *f = g_to_free;
		while (f) {
			struct free_list *n = f->next;
			on_free(f);
			f = n;
		}
		g_to_free = NULL;
	}
	
	return 0;
}

#endif
