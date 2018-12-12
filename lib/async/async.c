#include <os/async.h>

struct sockaddr_storage g_sockstorage;

#ifdef WIN32
HANDLE g_iocp;
LPFN_CONNECTEX g_ConnectEx;
LPFN_ACCEPTEX g_AcceptEx;
LPFN_TRANSMITFILE g_TransmitFile;
OVERLAPPED g_process_exit;
OVERLAPPED g_process_stopped;

#elif defined __linux__
int g_epoll;
sigset_t g_onagain;
int g_have_sigchld;
int g_have_sigterm;
struct free_list *g_to_free;

void on_sigchld(int sig) {
	g_have_sigchld = 1;
}
void on_sigterm(int sig) {
	g_have_sigterm = 1;
}
#else
int g_kqueue;
struct free_list *g_to_free;

void on_signal(int sig) {}
#endif
