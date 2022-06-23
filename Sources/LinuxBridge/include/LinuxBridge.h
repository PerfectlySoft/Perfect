#ifndef _LINUXBRIDGE_H_
#define _LINUXBRIDGE_H_

#include <sys/types.h>
#include <stdio.h>
#include <uuid/uuid.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <signal.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/sendfile.h>

#undef SIG_IGN
__sighandler_t SIG_IGN;

int linux_fcntl_get(int fd, int cmd);
int linux_fcntl_set(int fd, int cmd, int value);
int linux_open(const char *path, int oflag, mode_t mode);
int linux_errno();

#endif
