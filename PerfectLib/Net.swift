//
//  net.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/5/15.
//
//

import Foundation
import LibEvent

let isLittleEndian = Int(OSHostByteOrder()) == OSLittleEndian

let htons  = isLittleEndian ? _OSSwapInt16 : { $0 }
let htonl  = isLittleEndian ? _OSSwapInt32 : { $0 }
let htonll = isLittleEndian ? _OSSwapInt64 : { $0 }
let ntohs  = isLittleEndian ? _OSSwapInt16 : { $0 }
let ntohl  = isLittleEndian ? _OSSwapInt32 : { $0 }
let ntohll = isLittleEndian ? _OSSwapInt64 : { $0 }

let INVALID_SOCKET = Int32(-1)

/// Combines a socket with its family type & provides some utilities required by the LibEvent sub-system.
public struct SocketFileDescriptor {
	
	var fd: Int32, family: Int32
	
	init(fd: Int32, family: Int32 = AF_UNSPEC) {
		self.fd = fd
		self.family = family
	}
	
	func switchToNBIO() {
		if self.fd != INVALID_SOCKET {
			evutil_make_socket_nonblocking(fd)
			evutil_make_listen_socket_reuseable(fd)
		}
	}
}

