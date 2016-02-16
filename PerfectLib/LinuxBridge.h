#ifndef _LINUXBRIDGE_H_
#define _LINUXBRIDGE_H_

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <uuid/uuid.h>

int linux_open(const char *path, int oflag, mode_t mode);
int linux_errno();
u_int64_t htonll(u_int64_t host_longlong);
u_int64_t ntohll(u_int64_t host_longlong);
#endif
