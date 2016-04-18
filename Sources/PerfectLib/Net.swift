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

#else
import Darwin
	
let isLittleEndian = Int(OSHostByteOrder()) == OSLittleEndian
let htons  = isLittleEndian ? _OSSwapInt16 : { $0 }
let htonl  = isLittleEndian ? _OSSwapInt32 : { $0 }
let htonll = isLittleEndian ? _OSSwapInt64 : { $0 }
let ntohs  = isLittleEndian ? _OSSwapInt16 : { $0 }
let ntohl  = isLittleEndian ? _OSSwapInt32 : { $0 }
let ntohll = isLittleEndian ? _OSSwapInt64 : { $0 }
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
			let flags = fcntl(fd, F_GETFL, nil)
			guard flags >= 0 else {
				return
			}
			let _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
			
			var one = Int32(1)
			setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(sizeof(Int32)))
		}
	}
}

