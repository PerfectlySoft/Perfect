
#include <sys/types.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include <signal.h>

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

int pthread_cond_timedwait_relative_np(pthread_cond_t * cond, pthread_mutex_t * mutx, const struct timespec * tmspec)
{
	struct timeval time;
	struct timespec timeout;
	gettimeofday(&time, NULL);
	timeout.tv_sec = time.tv_sec + tmspec->tv_sec;
	timeout.tv_nsec = (time.tv_usec * 1000) + tmspec->tv_nsec;

	timeout.tv_sec += timeout.tv_nsec / 1000000000;
	timeout.tv_nsec %= 1000000000;

	int i = pthread_cond_timedwait(cond, mutx, &timeout);
	return i;
}
