//
//  util.c
//  PerfectLib
//
//  Created by Kyle Jessup on 7/6/15.
//
//

#include <stdio.h>
#include <sys/fcntl.h>

int my_fcntl(int fd, int cmd, int value);

int my_fcntl(int fd, int cmd, int value)
{
	return fcntl(fd, cmd, value);
}