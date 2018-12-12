#pragma once
#ifdef WIN32
#define _WIN32_WINNT 0x0600

#include <os/c.h>
#include <ws2tcpip.h>
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <mstcpip.h>
#include <inttypes.h>

#pragma comment(lib, "ws2_32.lib")

struct async {
	// user setable
	void *udata;
	HANDLE fd;
	// internal
	OVERLAPPED read, write;
	async_t *accept;

	// IO completion ports are odd in that they send
	// you a message in both synchronous and asynchronous cases.
	// To make things simpler treat sync as an async and then
	// the main loop will handle the rest
	// to make things extra confusing this behaviour only seems to
	// happen with sockets and not pipes
	unsigned always_pending : 1;
};

CEXTERN HANDLE g_iocp;
CEXTERN LPFN_CONNECTEX g_ConnectEx;
CEXTERN LPFN_ACCEPTEX g_AcceptEx;
CEXTERN LPFN_TRANSMITFILE g_TransmitFile;
CEXTERN OVERLAPPED g_process_exit;
CEXTERN OVERLAPPED g_process_stopped;

static inline int async_init() {
	WSADATA wsa;
	WSAStartup(MAKEWORD(2,2), &wsa);

	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
 	GUID connect = WSAID_CONNECTEX;
	GUID accept = WSAID_ACCEPTEX;
	GUID transmit = WSAID_TRANSMITFILE;
	DWORD num;

	int err = WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER, &connect, sizeof(connect), (void*) &g_ConnectEx, sizeof(g_ConnectEx), &num, NULL, NULL)
		   || WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER, &accept, sizeof(accept), (void*) &g_AcceptEx, sizeof(g_AcceptEx), &num, NULL, NULL)
		   || WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER, &transmit, sizeof(transmit), (void*) &g_TransmitFile, sizeof(g_TransmitFile), &num, NULL, NULL);

	closesocket(sock);

	if (err) {
		syserror("get winsock pointer");
		return -1;
	}

	g_iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, (ULONG_PTR) NULL, 1);
	if (g_iocp == INVALID_HANDLE_VALUE) {
		syserror("create io completion port");
		return -1;
	}

	return 0;
}

#define SHUT_RD SD_RECEIVE
#define SHUT_WR SD_SEND
#define SHUT_RDWR SD_BOTH

static inline void async_shutdown(async_t *a, int type) {
	shutdown((SOCKET) a->fd, type);
}

static inline void async_close_socket(async_t *a) {
	closesocket((SOCKET) a->fd);
	a->fd = NULL;
}

static inline int async_read(async_t *a, char *buf, int sz) {
	DWORD read;
	assert(!a->accept);
	BOOL ok = ReadFile(a->fd, buf, sz, &read, &a->read);
	debug("async_read async %p, buf %p, bufsz %d, always_pending %d, returned %d, read %d", a, buf, sz, a->always_pending, ok, read);
	if (ok && !a->always_pending) {
		return (int) read;
	} else if (ok || GetLastError() == WSA_IO_PENDING) {
		return 0;
	} else {
		syserror("async_read");
		return -1;
	}
}

static inline int async_write(async_t *a, char *buf, int sz) {
	DWORD written;
	assert(!a->accept);
	BOOL ok = WriteFile(a->fd, buf, sz, &written, &a->write);
	debug("async_write async %p, buf %p, bufsz %d, always_pending %d, returned %d, wrote %d", a, buf, sz, a->always_pending, ok, written);
	if (ok && !a->always_pending) {
		return (int) written;
	} else if (ok || GetLastError() == WSA_IO_PENDING) {
		return 0;
	} else {
		syserror("async_write");
		return -1;
	}
}

static inline int async_send_file(async_t *sock, async_t *file, char *hdr, int hdrsz, int64_t off, int filelen) {
	TRANSMIT_FILE_BUFFERS fb = {0};
	fb.Head = hdr;
	fb.HeadLength = hdrsz;
	assert(!sock->accept && !file->accept);
	((LARGE_INTEGER*) &sock->write.Offset)->QuadPart = off;
	BOOL ok = g_TransmitFile((SOCKET) sock->fd, file->fd, filelen, 0, &sock->write, &fb, 0);
	debug("async_send_file async %p, file %p, hdr %p, hdrsz %d, off %" PRId64 ", len %d, returned %d", sock, file, hdr, hdrsz, off, filelen, ok);
	if (ok || GetLastError() == WSA_IO_PENDING) {
		return 0;
	} else {
		syserror("async_send_file");
		return -1;
	}
}

static inline int async_accept(async_t *a, int family, async_t *child, char *buf, int bufsz) {
	assert(bufsz >= ASYNC_ACCEPT_BUFSZ);


	child->always_pending = 1;
	child->accept = NULL;
	child->fd = (HANDLE) WSASocket(family, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);

	CreateIoCompletionPort(child->fd, g_iocp, (ULONG_PTR) child, 1);
	int ssz = sizeof(struct sockaddr_storage);
	a->accept = child;

	DWORD transferred;
	BOOL ok = g_AcceptEx((SOCKET) a->fd, (SOCKET) child->fd, buf, (DWORD) (bufsz - 2 * ssz), ssz, ssz, &transferred, &a->read);
	debug("async_accept async %p, family %d, child %p, buf %p, bufsz %d, returned %d, read %d", a, family, child, buf, bufsz, ok, transferred);
	if (ok || GetLastError() == WSA_IO_PENDING) {
		return ASYNC_PENDING;
	} else {
		syserror("async_accept");
		return ASYNC_ERROR;
	}
}

static inline int async_bind_udp(async_t *a, struct sockaddr *sa) {
	SOCKET fd = WSASocket(sa->sa_family, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (fd == INVALID_SOCKET) {
		syserror("create listening socket");
		return -1;
	}

	if (bind(fd, sa, socksize(sa))) {
		syserror("bind");
		return -1;
	}

	a->fd = (HANDLE) fd;
	a->accept = NULL;
	CreateIoCompletionPort(a->fd, g_iocp, (ULONG_PTR) a, 1);

	return 0;
}

static inline int async_listen_tcp(async_t *a, struct sockaddr *sa) {
	SOCKET fd = WSASocket(sa->sa_family, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (fd == INVALID_SOCKET) {
		syserror("create listening socket");
		return -1;
	}

	if (bind(fd, sa, socksize(sa))) {
		syserror("bind");
		closesocket(fd);
		return -1;
	}

	if (listen(fd, SOMAXCONN)) {
		syserror("listen");
		closesocket(fd);
		return -1;
	}

	a->fd = (HANDLE) fd;
	a->accept = NULL;
	CreateIoCompletionPort(a->fd, g_iocp, (ULONG_PTR) a, 1);

	return 0;
}

static inline int async_listen_unix(async_t *a, const char *path) {
	(void) a;
	(void) path;
	return -1;
}

static inline int async_connect(async_t *a, struct sockaddr *sa, char *msg, int mlen) {
	SOCKET fd = WSASocket(sa->sa_family, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (fd == INVALID_SOCKET) {
		syserror("socket");
		return ASYNC_ERROR;
	}

	int sasz = socksize(sa);
	struct sockaddr_storage ss;
	memcpy(&ss, sa, sasz);

	uint16_t port;
	if (sa->sa_family == AF_INET6) {
		port = ntohs(((struct sockaddr_in6*) &ss)->sin6_port);
		((struct sockaddr_in6*) &ss)->sin6_port = 0;
	} else {
		port = ntohs(((struct sockaddr_in*) &ss)->sin_port);
		((struct sockaddr_in*) &ss)->sin_port = 0;
	}

	if (bind(fd, (struct sockaddr*) &ss, sasz)) {
		syserror("bind");
		closesocket(fd);
		return ASYNC_ERROR;
	}

	a->always_pending = 1;
	a->fd = (HANDLE) fd;
	a->accept = NULL;
	CreateIoCompletionPort(a->fd, g_iocp, (ULONG_PTR) a, 1);

	DWORD sent;
	BOOL ok = g_ConnectEx(fd, sa, sasz, msg, mlen, &sent, &a->write);
	debug("async_conenct async %p, port %d, msg %p, len %d, returned %d, sent %d", a, port, msg, mlen, ok, sent);
	if (ok || GetLastError() == WSA_IO_PENDING) {
		return ASYNC_PENDING;
	} else {
		syserror("connectex");
		closesocket(fd);
		return ASYNC_ERROR;
	}
}

// Process cleanup is a bit complex on windows because we have 
// to use a side thread (via RegisterForSingleObject) to watch
// the process handle. With a process that self exits the process is as follows:
// 1. exe is spawned via proc_start in os_spawn. This sets p->running.
// 2. exe quits triggering on_process_exit in a side thread
// 3. on_process_exit posts message to the main loop
// 4. main loop calls os_stop if it hasn't been called already
// 5. os_stop posts another message to the main loop
// 6. main loop calls proc_reset

// The reason for this is that a stop call can happen intermixed with the process exit.
// #4 checks that we only call os_stop once as stop may have been called after
// the on_process_exit but before the message is processed on the main loop.
// os_stop itself posts back to the main loop, ensuring that the main loop stop
// processing always happens after the processing of an exit request

static inline void async_stop_process(struct os_proc *proc, int exit_code) {
	// always call kill group even if we've been notified of the exit
	// that way we also kill the rest of the group
	debug("async_stop_process: proc %p, exit %d", proc, exit_code);
	proc_kill_group(proc, exit_code);
	UnregisterWaitEx(proc->waiter, INVALID_HANDLE_VALUE);
	// at this point on_process_exit won't be called - UnregisterWait is synchronous
	// but there may still be a message posted to the main loop mid flight
	// hence post another to make sure we're after it
	PostQueuedCompletionStatus(g_iocp, exit_code, (ULONG_PTR) proc, &g_process_stopped);
}

static void CALLBACK on_process_exit(PVOID param, BOOLEAN TimerOrWaitFired) {
	(void) TimerOrWaitFired;
	struct os_proc *p = (struct os_proc*) param;
	assert(p->running);
	DWORD exit_code;
	GetExitCodeProcess(p->exe, &exit_code);
	debug("on_process_exit: proc %p, exit_code %d", p, exit_code);
	PostQueuedCompletionStatus(g_iocp, exit_code, (ULONG_PTR) p, &g_process_exit);
}

static inline int async_open_process(struct os_proc *proc, const char *pidfile) {
	if (proc_open_pidfile(proc, pidfile)) {
		return -1;
	}

	if (!RegisterWaitForSingleObject(&proc->waiter, proc->exe, &on_process_exit, proc, INFINITE, WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE)) {
		proc_kill_group(proc, 0);
		proc_reset(proc);
		return -1;
	}

	return 0;
}

static inline int async_start_process(struct os_proc *proc, const char **argv, async_t *in, async_t *out) {
	char pn[] = "\\\\.\\pipe\\httpd-pipe-X-XXXXXXXX-XXXXXXXXXXXXXXXX";
	sprintf(pn + sizeof(pn) - 28, "i-%08X-%p", GetCurrentProcessId(), (void*) proc);

	HANDLE inr = CreateNamedPipe(pn, PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED, 0, 1, 4096, 4096, 0, NULL);
	HANDLE inw = CreateFile(pn, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, 0, NULL);

	sprintf(pn + sizeof(pn) - 28, "o-%08X-%p", GetCurrentProcessId(), (void*) proc);

	HANDLE outr = CreateNamedPipe(pn, PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED, 0, 1, 4096, 4096, 0, NULL);
	HANDLE outw = CreateFile(pn, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, 0, NULL);

	if (inr == INVALID_HANDLE_VALUE || inw == INVALID_HANDLE_VALUE || outr == INVALID_HANDLE_VALUE || outw == INVALID_HANDLE_VALUE) {
		goto err;
	}

	proc->in = inr;
	proc->out = outw;
	proc->err = pipe_stderr();

	if (proc_start(proc, argv, PROC_NEW_GROUP)) {
		goto err;
	}

	CloseHandle(inr);
	CloseHandle(outw);

	in->accept = NULL;
	out->accept = NULL;
	in->always_pending = 0;
	out->always_pending = 0;

	in->fd = inw;
	out->fd = outr;

	debug("async_start_process: proc %p, argv0 %s, in %p, out %p", proc, argv[0], in, out);

	CreateIoCompletionPort(inw, g_iocp, (ULONG_PTR) in, 1);
	CreateIoCompletionPort(outr, g_iocp, (ULONG_PTR) out, 1);

	if (!RegisterWaitForSingleObject(&proc->waiter, proc->exe, &on_process_exit, proc, INFINITE, WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE)) {
		proc_kill_group(proc, 0);
		proc_reset(proc);
		goto err;
	}

	return 0;

err:
	CloseHandle(inr);
	CloseHandle(inw);
	CloseHandle(outr);
	CloseHandle(outw);
	return -1;
}

static inline int64_t async_open_file(async_t *a, const char *path, uint64_t *petag) {
	HANDLE fd = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
	if (fd == INVALID_HANDLE_VALUE) {
		return ASYNC_ERROR;
	}

	LARGE_INTEGER sz;
	if (!GetFileSizeEx(fd, &sz)) {
		CloseHandle(fd);
		return ASYNC_ERROR;
	}

	if (petag) {
		FILETIME mod;
		if (!GetFileTime(fd, NULL, NULL, &mod)) {
			CloseHandle(fd);
			return ASYNC_ERROR;
		}
		uint64_t etag = (((uint64_t) sz.LowPart) << 32) | (uint64_t) mod.dwLowDateTime;
		if (etag == *petag) {
			CloseHandle(fd);
			return ASYNC_NOT_MODIFIED;
		}
		*petag = etag;
	}

	debug("async_open_file: async %p, path %s", a, path);

	a->fd = fd;
	a->accept = NULL;
	a->always_pending = 0;
	CreateIoCompletionPort(fd, g_iocp, (ULONG_PTR) a, 1);

	return (int64_t) sz.QuadPart;
}

static inline void async_close_file(async_t *a) {
	CloseHandle(a->fd);
	a->fd = NULL;
}

static inline int async_poll(os_duration_t wait, free_cb on_free, accept_cb on_accept, async_cb on_read, async_cb on_write, child_cb on_child, os_steady_t *pnow) {
	OVERLAPPED_ENTRY ev[64];
	unsigned long num;
	DWORD timeout = (wait == OS_TIME_MAX) ? INFINITE : (DWORD) to_ms(wait);
	debug("poll start timeout %u", timeout);
	BOOL ok = GetQueuedCompletionStatusEx(g_iocp, ev, 64, &num, timeout, FALSE);

	*pnow = os_steady();

	if (!ok) {
		if (GetLastError() == WAIT_TIMEOUT) {
			return 0;
		} else {
			return -1;
		}
	}

	debug("poll returned %u events", num);
	for (unsigned long i = 0; i < num; i++) {
		debug("poll event %u: ol %p, key %p", i, (void*) ev[i].lpOverlapped, (void*) ev[i].lpCompletionKey);
	}

	for (unsigned long i = 0; i < num; i++) {
		OVERLAPPED *ol = ev[i].lpOverlapped;
		int transferred = (int) ev[i].dwNumberOfBytesTransferred;
		void *key = (void*) ev[i].lpCompletionKey;
		async_t *a = (async_t*) key;

		if (on_free && ol == NULL) {
			// async_free must have been called
			debug("poll free %u: object %p", i, key);
			on_free((struct free_list*) key);

		} else if (on_child && ol == &g_process_stopped) {
			// we either initiated the stop or the process exited
			// either way the callback has been deregistered
			// the child callback should call proc_reset
			struct os_proc *proc = (struct os_proc*) key;
			debug("poll stop %u: proc %p, code %d", i, proc, transferred);
			on_child(proc, proc_pid(proc), transferred);

		} else if (on_child && ol == &g_process_exit) {
			// the process exited and the registered callback is
			// notifying us. in all cases we want to make sure
			// async_stop_process is called so that the rest of the
			// job is cleaned up. Also note that async_stop_process
			// may have already been called right after the callback
			// was fired. Hence the check on proc->stopping
			struct os_proc *proc = (struct os_proc*) key;
			debug("poll exit %u: proc %p, stopped %u, code %d", i, proc, proc->stopping, transferred);
			if (!proc->stopping) {
				// we did not initiate the exit
				async_stop_process(proc, transferred);
			}

		} else if (a->accept) {
			debug("poll accept %u: async %p, accept %p, received %d", i, a, a->accept, transferred);
			// async_accept has finished
			assert(on_accept != NULL && ol == &a->read);
			on_accept(a, a->accept, transferred);

		} else if (ol == &a->read && a->fd) {
			// a->fd is set to NULL by async_close_socket and async_close_file
			// if the user prematuraly closes the handle, any pending requests are terminated
			// we don't want these to bubble up to the user
			debug("poll read %u: async %p, received %d", i, a, transferred);
			// async_read has finished
			assert(on_read != NULL);
			on_read(a, transferred ? transferred : -1);

		} else if (ol == &a->write && a->fd) {
			debug("poll write %u: async %p, wrote %d", i, a, transferred);
			// async_write or async_connect has finished
			assert(on_write != NULL);
			on_write(a, transferred ? transferred : -1);
		}
	}

	return 0;
}

static inline void async_free(struct free_list *node) {
	// post a message to the completion port, this way it will be picked
	// up on the next poll and thus after any queued messages which may
	// reference the node
	PostQueuedCompletionStatus(g_iocp, 0, (ULONG_PTR) node, NULL);
}

#endif
