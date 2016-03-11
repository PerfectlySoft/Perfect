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

import LibEvent

#if os(Linux)

#else
let isLittleEndian = Int(OSHostByteOrder()) == OSLittleEndian
let htons  = isLittleEndian ? _OSSwapInt16 : { $0 }
let htonl  = isLittleEndian ? _OSSwapInt32 : { $0 }
let htonll = isLittleEndian ? _OSSwapInt64 : { $0 }
let ntohs  = isLittleEndian ? _OSSwapInt16 : { $0 }
let ntohl  = isLittleEndian ? _OSSwapInt32 : { $0 }
let ntohll = isLittleEndian ? _OSSwapInt64 : { $0 }
#endif

let invalidSocket = Int32(-1)

/// Combines a socket with its family type & provides some utilities required by the LibEvent sub-system.
public struct SocketFileDescriptor {
	
	var fd: Int32, family: Int32
	var isValid: Bool { return self.fd != invalidSocket }
	
	init(fd: Int32, family: Int32 = AF_UNSPEC) {
		self.fd = fd
		self.family = family
	}
	
	func switchToNBIO() {
		if self.fd != invalidSocket {
			evutil_make_socket_nonblocking(fd)
			evutil_make_listen_socket_reuseable(fd)
		}
	}
}

