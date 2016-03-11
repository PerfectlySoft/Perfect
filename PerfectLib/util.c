//
//  util.c
//  PerfectLib
//
//  Created by Kyle Jessup on 7/6/15.
//	Copyright (C) 2015 PerfectlySoft, Inc.
//
//===----------------------------------------------------------------------===//
//
// This source file is part of the Perfect.org open source project
//
// Copyright (c) 2015 - 2016 PerfectlySoft Inc. and the Perfect project authors
// Licensed under Apache License v2.0
//
// See http://perfect.org/licensing.html for license information
//
//===----------------------------------------------------------------------===//
//


#include <stdio.h>
#include <sys/fcntl.h>

int my_fcntl(int fd, int cmd, int value);

int my_fcntl(int fd, int cmd, int value)
{
	return fcntl(fd, cmd, value);
}