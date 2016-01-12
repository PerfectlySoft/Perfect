
#include "LinuxBridge.h"
#include <arpa/inet.h>

int linux_open(const char *path, int oflag, mode_t mode)
{
	return open(path, oflag, mode);
}

int linux_errno()
{
	return errno;
}

u_int64_t htonll(u_int64_t host_longlong)
{
    int x = 1;
    if(*(char *)&x == 1)
        return ((((u_int64_t)htonl(host_longlong)) << 32) + htonl(host_longlong >> 32));
    else
        return host_longlong;
}

u_int64_t ntohll(u_int64_t host_longlong)
{
    int x = 1;
    if(*(char *)&x == 1)
        return ((((u_int64_t)ntohl(host_longlong)) << 32) + ntohl(host_longlong >> 32));
    else
        return host_longlong;
}
