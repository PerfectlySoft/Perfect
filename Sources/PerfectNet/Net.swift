//
//  net.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/5/15.
//	Copyright (C) 2015 PerfectlySoft, Inc.
//
// ===----------------------------------------------------------------------===//
//
// This source file is part of the Perfect.org open source project
//
// Copyright (c) 2015 - 2016 PerfectlySoft Inc. and the Perfect project authors
// Licensed under Apache License v2.0
//
// See http://perfect.org/licensing.html for license information
//
// ===----------------------------------------------------------------------===//
//

import PerfectThread
import Foundation

#if os(Linux)
import SwiftGlibc
import LinuxBridge

var errno: Int32 {
    return linux_errno()
}

#else
import Darwin
#endif

public typealias SocketType = Int32

public let invalidSocket = SocketType(-1)

#if os(Linux)
	extension sockaddr_storage {
		var ss_len: Int8 {
			switch Int32(self.ss_family) {
			case AF_INET:
				return Int8(MemoryLayout<sockaddr_in>.size)
			case AF_INET6:
				return Int8(MemoryLayout<sockaddr_in6>.size)
			case AF_UNIX:
				return Int8(MemoryLayout<sockaddr_un>.size)
			default:
				return Int8(MemoryLayout<sockaddr>.size)
			}
		}
	}

	extension addrinfo {
		init(ai_flags: Int32, ai_family: Int32, ai_socktype: __socket_type, ai_protocol: Int32, ai_addrlen: socklen_t, ai_canonname: UnsafeMutablePointer<Int8>!, ai_addr: UnsafeMutablePointer<sockaddr>!, ai_next: UnsafeMutablePointer<addrinfo>!) {
			self.init(ai_flags: ai_flags, ai_family: ai_family, ai_socktype: Int32(ai_socktype.rawValue), ai_protocol: ai_protocol, ai_addrlen: ai_addrlen, ai_addr: ai_addr, ai_canonname: ai_canonname, ai_next: ai_next)
		}
	}
#endif

public extension UnsignedInteger {
	var hostIsLittleEndian: Bool { return 256.littleEndian == 256 }
}

public protocol BytesSwappingUnsignedInteger: UnsignedInteger {
	var byteSwapped: Self { get }
}

public extension BytesSwappingUnsignedInteger {
	var hostToNet: Self {
		return self.hostIsLittleEndian ? self.byteSwapped : self
	}
	var netToHost: Self {
		return self.hostIsLittleEndian ? self.byteSwapped : self
	}
}

extension UInt16: BytesSwappingUnsignedInteger {}
extension UInt32: BytesSwappingUnsignedInteger {}
extension UInt64: BytesSwappingUnsignedInteger {}

public enum PerfectNetError: Error {
	/// A network related error code and message.
	case networkError(Int32, String)
}

func ThrowNetworkError(file: String = #file, function: String = #function, line: Int = #line) throws -> Never {
	let err = errno
	let msg = String(validatingUTF8: strerror(err))!
	throw PerfectNetError.networkError(err, msg + " \(file) \(function) \(line)")
}

final class ReferenceBuffer {
	var a: [UInt8]
	let size: Int
	init(size: Int) {
		self.size = size
		self.a = [UInt8](repeating: 0, count: size)
	}
	func withUnsafeMutableBytes<R>(advanced by: Int, _ body: (UnsafeMutableRawPointer?) -> R) -> R {
		return a.withUnsafeMutableBytes { (p: UnsafeMutableRawBufferPointer) -> R in
			return body(p.baseAddress?.advanced(by: by))
		}
	}
}

/// Combines a socket with its family type & provides some utilities required by the LibEvent sub-system.
public struct SocketFileDescriptor {

	public var fd: SocketType, family: Int32
	public var isValid: Bool { return self.fd != invalidSocket }

	public init(fd: SocketType, family: Int32 = AF_UNSPEC) {
		self.fd = fd
		self.family = family
	}

	public func switchToNonBlocking() {
        guard self.fd != invalidSocket else {
            return
        }
	#if os(Linux)
        let flags = linux_fcntl_get(fd, F_GETFL)
        guard flags >= 0 else {
            return
        }
        _ = linux_fcntl_set(fd, F_SETFL, flags | O_NONBLOCK)
	#else
        let flags = fcntl(fd, F_GETFL)
        guard flags >= 0 else {
            return
        }
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
	#endif
        var one = Int32(1)
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, UInt32(MemoryLayout<Int32>.size))
	#if os(OSX) || os(iOS) || os(tvOS)
		setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, UInt32(MemoryLayout<Int32>.size))
	#endif
	}

    public func switchToBlocking() {
        guard self.fd != invalidSocket else {
            return
        }

    #if os(Linux)
        let flags = linux_fcntl_get(fd, F_GETFL)
        guard flags >= 0 else {
            return
        }
        _ = linux_fcntl_set(fd, F_SETFL, flags & ~O_NONBLOCK)
    #else
        let flags = fcntl(fd, F_GETFL)
        guard flags >= 0 else {
            return
        }
        _ = fcntl(fd, F_SETFL, flags & ~O_NONBLOCK)
    #endif
    }
}

open class Net {
	public var fd: SocketFileDescriptor = SocketFileDescriptor(fd: invalidSocket, family: AF_UNSPEC)
	public var isValid: Bool { return self.fd.isValid }

	/// Create a new object with an initially invalid socket file descriptor.
	public init() {

	}

	deinit {
		close()
	}

	#if os(Linux)
	public func initSocket(family: Int32, type: __socket_type) {
		initSocket(family: family, type: Int32(type.rawValue))
	}
	#endif

	open func initSocket(family: Int32) {}

	open func shutdown() {
		if fd.fd != invalidSocket {
			#if os(Linux)
			_ = SwiftGlibc.shutdown(fd.fd, Int32(SHUT_RDWR))
			#else
			_ = Darwin.shutdown(fd.fd, SHUT_RDWR)
			#endif
		}
	}

	/// Allocates a new socket if it has not already been done.
	/// The functions `bind` and `connect` will call this method to ensure the socket has been allocated.
	/// Sub-classes should override this function in order to create their specialized socket.
	/// All sub-class sockets should be switched to utilize non-blocking IO by calling `SocketFileDescriptor.switchToNBIO()`.
	func initSocket(family: Int32, type: Int32) {
		if fd.fd == invalidSocket {
			fd.fd = socket(family, type, 0)
			fd.family = family
			fd.switchToNonBlocking()
		}
	}
//
//	func makeAddress(_ sin: inout sockaddr_storage, host: String, port: UInt16) -> Int {
//		let aiFlags: Int32 = 0
//		let family: Int32 = AF_UNSPEC
//		let bPort = port.bigEndian
//		var hints = addrinfo(ai_flags: aiFlags, ai_family: family, ai_socktype: SOCK_STREAM, ai_protocol: 0, ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
//		var resultList = UnsafeMutablePointer<addrinfo>(bitPattern: 0)
//		var result = getaddrinfo(host, nil, &hints, &resultList)
//		while EAI_AGAIN == result {
//			Threading.sleep(seconds: 0.1)
//			result = getaddrinfo(host, nil, &hints, &resultList)
//		}
//		if result == EAI_NONAME {
//			hints = addrinfo(ai_flags: aiFlags, ai_family: AF_INET6, ai_socktype: SOCK_STREAM, ai_protocol: 0, ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
//			result = getaddrinfo(host, nil, &hints, &resultList)
//		}
//		if result == 0, var resultList = resultList {
//			defer {
//				freeaddrinfo(resultList)
//			}
//			guard let addr = resultList.pointee.ai_addr else {
//				return -1
//			}
//			switch Int32(addr.pointee.sa_family) {
//			case AF_INET6:
//				memcpy(&sin, addr, MemoryLayout<sockaddr_in6>.size)
//				UnsafeMutablePointer(&sin).withMemoryRebound(to: sockaddr_in6.self, capacity: 1) {
//					$0.pointee.sin6_port = in_port_t(bPort)
//				}
//			case AF_INET:
//				memcpy(&sin, addr, MemoryLayout<sockaddr_in>.size)
//				UnsafeMutablePointer(&sin).withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
//					$0.pointee.sin_port = in_port_t(bPort)
//				}
//			default:
//				return -1
//			}
//		} else {
//			return -1
//		}
//		return 0
//	}

	func isEAgain(err: Int) -> Bool {
		return err == -1 && errno == EAGAIN
	}

	/// Bind the socket on the given port and optional local address
	/// - parameter port: The port on which to bind
	/// - parameter address: The the local address, given as a string, on which to bind. Defaults to "0.0.0.0".
	/// - throws: PerfectError.NetworkError
	public func bind(port prt: UInt16, address: String = "0.0.0.0") throws {
		guard var addr = NetAddress(host: address, port: prt)?.addr else {
			try ThrowNetworkError()
		}
		initSocket(family: Int32(addr.ss_family))
		let len = socklen_t(addr.ss_len)
		let bRes: Int32 = withUnsafeBytes(of: &addr) {
			let saddr = $0.bindMemory(to: sockaddr.self).baseAddress
			#if os(Linux)
				return SwiftGlibc.bind(self.fd.fd, saddr, len)
			#else
				return Darwin.bind(self.fd.fd, saddr, len)
			#endif
		}
		if bRes == -1 {
			try ThrowNetworkError()
		}
	}

	/// Switches the socket to server mode. Socket should have been previously bound using the `bind` function.
	public func listen(backlog: Int32 = 128) {
		#if os(Linux)
			_ = SwiftGlibc.listen(fd.fd, backlog)
		#else
			_ = Darwin.listen(fd.fd, backlog)
		#endif
	}

	/// Shuts down and closes the socket.
	/// The object may be reused.
	public func close() {
		if fd.fd != invalidSocket {
			shutdown()
			#if os(Linux)
			_ = SwiftGlibc.close(fd.fd)
			#else
			_ = Darwin.close(fd.fd)
			#endif
			fd.fd = invalidSocket
		}
	}

}

extension Net: Equatable {
	public static func == (lhs: Net, rhs: Net) -> Bool {
		return lhs.fd.fd == rhs.fd.fd
	}
}
