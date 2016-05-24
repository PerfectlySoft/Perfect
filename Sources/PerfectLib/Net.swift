//
//  net.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/5/15.
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

#if os(Linux)
import SwiftGlibc
import LinuxBridge
#else
import Darwin
#endif

public typealias SocketType = Int32

let invalidSocket = SocketType(-1)

/// Combines a socket with its family type & provides some utilities required by the LibEvent sub-system.
public struct SocketFileDescriptor {

	var fd: SocketType, family: Int32
	var isValid: Bool { return self.fd != invalidSocket }

	init(fd: SocketType, family: Int32 = AF_UNSPEC) {
		self.fd = fd
		self.family = family
	}

	func switchToNBIO() {
		if self.fd != invalidSocket {
#if os(Linux)
			let flags = linux_fcntl_get(fd, F_GETFL)
			guard flags >= 0 else {
				return
			}
			let _ = linux_fcntl_set(fd, F_SETFL, flags | O_NONBLOCK)
#else
			let flags = fcntl(fd, F_GETFL)
			guard flags >= 0 else {
				return
			}
			let _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
#endif
			var one = Int32(1)
			setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(sizeof(Int32)))
		}
	}
}
