#ifndef _LINUXBRIDGE_H_
#define _LINUXBRIDGE_H_

#include <sys/types.h>
#include <uuid/uuid.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <signal.h>

#undef SIG_IGN
extern __sighandler_t SIG_IGN;

int linux_open(const char *path, int oflag, mode_t mode);
int linux_errno();
int linux_fcntl_get(int fd, int cmd);
int linux_fcntl_set(int fd, int cmd, int value);
unsigned long long htonll(unsigned long long host_longlong);
unsigned long long ntohll(unsigned long long host_longlong);
int pthread_cond_timedwait_relative_np(void * cond, void * mutx, const struct timespec * tmspec);

#endif
