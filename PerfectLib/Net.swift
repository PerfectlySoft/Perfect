//
//  net.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/5/15.
//	Copyright (C) 2015 PerfectlySoft, Inc.
//
//	This program is free software: you can redistribute it and/or modify
//	it under the terms of the GNU Affero General Public License as
//	published by the Free Software Foundation, either version 3 of the
//	License, or (at your option) any later version, as supplemented by the
//	Perfect Additional Terms.
//
//	This program is distributed in the hope that it will be useful,
//	but WITHOUT ANY WARRANTY; without even the implied warranty of
//	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//	GNU Affero General Public License, as supplemented by the
//	Perfect Additional Terms, for more details.
//
//	You should have received a copy of the GNU Affero General Public License
//	and the Perfect Additional Terms that immediately follow the terms and
//	conditions of the GNU Affero General Public License along with this
//	program. If not, see <http://www.perfect.org/AGPL_3_0_With_Perfect_Additional_Terms.txt>.
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

