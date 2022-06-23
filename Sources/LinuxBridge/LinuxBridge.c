
#include "LinuxBridge.h"

#undef SIG_IGN
__sighandler_t SIG_IGN = (__sighandler_t)1;

int linux_fcntl_get(int fd, int cmd)
{
	return fcntl(fd, cmd);
}

int linux_fcntl_set(int fd, int cmd, int value)
{
	return fcntl(fd, cmd, value);
}

int linux_open(const char *path, int oflag, mode_t mode)
{
	return open(path, oflag, mode);
}

int linux_errno()
{
	return errno;
}
