#ifndef _LINUXBRIDGE_H_
#define _LINUXBRIDGE_H_

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

int linux_open(const char *path, int oflag, mode_t mode);
int linux_errno();

#endif