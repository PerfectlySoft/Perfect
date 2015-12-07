
#include "LinuxBridge.h"

int linux_open(const char *path, int oflag, mode_t mode)
{
	return open(path, oflag, mode);
}

int linux_errno()
{
	return errno;
}

