#pragma once
#if !defined __linux__ && !defined WIN32
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>

struct async {
    // user setable
    void *udata;
    int fd;
    // internal
    async_t *accept;
    int events;
};

#define ASYNC_FLAG_READ 1
#define ASYNC_FLAG_WRITE 2

CEXTERN int g_kqueue;
CEXTERN struct free_list *g_to_free;

CFUNC void on_signal(int sig);

static int async_init() {
    assert(!g_kqueue);
    g_kqueue = kqueue();
    if (g_kqueue < 0) {
        syserror("kqueue init");
        return -1;
    }

    struct kevent ev[2];
    EV_SET(ev, SIGCHLD, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
    EV_SET(ev+1, SIGTERM, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
    
    // need to have some signal callback, otherwise the signal may be fully masked

	if (signal(SIGTERM, &on_signal)
    || signal(SIGCHLD, &on_signal) 
    || kevent(g_kqueue, ev, 2, NULL, 0, NULL)) {
		syserror("signal setup");
		return -1;
	}

    return 0;
}

static inline void watch_read(async_t *a) {
    struct kevent ev;
    EV_SET(&ev, a->fd, EVFILT_READ, EV_ADD|EV_CLEAR, 0, 0, a);
    if (kevent(g_kqueue, &ev, 1, NULL, 0, NULL)) {
        syserror("kevent");
    }
}

static inline void watch_write(async_t *a) {
    struct kevent ev;
    EV_SET(&ev, a->fd, EVFILT_WRITE, EV_ADD|EV_CLEAR, 0, 0, a);
    if (kevent(g_kqueue, &ev, 1, NULL, 0, NULL)) {
        syserror("kevent");
    }
}

static inline void watch_both(async_t *a) {
    struct kevent ev[2];
    EV_SET(&ev[0], a->fd, EVFILT_READ, EV_ADD|EV_CLEAR, 0, 0, a);
    EV_SET(&ev[1], a->fd, EVFILT_WRITE, EV_ADD|EV_CLEAR, 0, 0, a);
    if (kevent(g_kqueue, ev, 2, NULL, 0, NULL)) {
        syserror("kevent");
    }
}

static inline int async_poll(os_duration_t wait, free_cb on_free, accept_cb on_accept, async_cb on_read, async_cb on_write, child_cb on_child, os_steady_t *pnow) {
    struct timespec tv, *ptv = NULL;
    if (wait != OS_TIME_MAX) {
        to_timespec(&tv, wait);
        ptv = &tv;
    }

    struct kevent ev[64];
    int num = kevent(g_kqueue, NULL, 0, ev, 64, ptv);

    if (num < 0 && errno != EINTR) {
        syserror("kevent");
        return -1;
    }

    *pnow = os_steady();

    for (int i = 0; i < num; i++) {
        async_t *a = (async_t*) ev[i].udata;

        switch (ev[i].filter) {
        case EVFILT_SIGNAL:
            switch (ev[i].ident) {
            case SIGCHLD:
                if (on_child) {
                    int pid, sts;
                    while ((pid = waitpid(-1, &sts, WNOHANG)) > 0) {
                        on_child(NULL, pid, sts);
                    }
                }
                break;
            case SIGTERM:
                return 1;
            }
            break;

        case EVFILT_READ:
            if (a->accept) {
                assert(on_accept != NULL);
                // posix async_accept doesn't use buf, bufsz, and family
                if (async_accept(a, 0, a->accept, NULL, 0) >= 0) {
                    on_accept(a, a->accept, 0);
                }
            } else if (on_read && (a->events & ASYNC_FLAG_READ)) {
                a->events &= ~ASYNC_FLAG_READ;
                on_read(a, 0);
            }
            break;

        case EVFILT_WRITE:
            if (on_write && (a->events & ASYNC_FLAG_WRITE)) {
                a->events &= ~ASYNC_FLAG_WRITE;
                on_write(a, 0);
            }
            break;
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
