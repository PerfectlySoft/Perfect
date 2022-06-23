//
//  NetUDP.swift
//  PerfectNet
//
//  Created by Kyle Jessup on 2017-01-23.
//	Copyright (C) 2016 PerfectlySoft, Inc.
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
//

#if os(Linux)
	import SwiftGlibc
#else
	import Darwin
#endif

public class NetUDP: Net {

	/// Creates an instance which will use the given file descriptor
	/// - parameter fd: The pre-existing file descriptor
	public convenience init(fd: Int32) {
		self.init()
		self.fd.fd = fd
		self.fd.family = AF_INET
		self.fd.switchToNonBlocking()
	}

	public override init() {
		super.init()
		self.initSocket(family: AF_INET)
	}

	public override func initSocket(family: Int32) {
		#if os(Linux)
		initSocket(family: family, type: 2)
		#else
		initSocket(family: family, type: SOCK_DGRAM)
		#endif
	}

	/// Read up to the indicated number of bytes and deliver them and the sender's address on the provided callback.
	/// - parameter count: The number of bytes to read
	/// - parameter timeoutSeconds: The number of seconds to wait for the requested number of bytes. A timeout value of negative one indicates that the request should have no timeout.
	/// - parameter completion: The callback on which the results will be delivered. If the timeout occurs before the requested number of bytes have been read, a nil object will be delivered to the callback.
	public func readBytes(count: Int, timeoutSeconds: Double, completion: @escaping (() throws -> ([UInt8], NetAddress)?) -> ()) {
		var a = [UInt8](repeating: 0, count: count)
		var addr = sockaddr_storage()
		var addrSize = socklen_t(MemoryLayout<sockaddr_storage>.size)
		let size = a.withUnsafeMutableBytes { ptr in withUnsafeMutableBytes(of: &addr) { addrPtr in
				recvfrom(fd.fd, ptr.baseAddress, count, 0, addrPtr.bindMemory(to: sockaddr.self).baseAddress, &addrSize)
			}
		}
		if size > 0, let addr = NetAddress(addr: addr) {
			completion({ return (Array(a[0..<size]), addr) })
		} else if size == 0 {
			completion({ return nil })
		} else if isEAgain(err: size) && timeoutSeconds > 0 {
			NetEvent.add(socket: fd.fd, what: .read, timeoutSeconds: timeoutSeconds) { [weak self] _, w in
				if case .read = w {
					self?.readBytes(count: count, timeoutSeconds: 0.0, completion: completion)
				} else {
					completion({ return nil })
				}
			}
		} else {
			let err = errno
			completion({
				let msg = String(validatingUTF8: strerror(err))!
				throw PerfectNetError.networkError(err, msg + " \(#file) \(#function) \(#line)")
			})
		}
	}

	/// Write the indicated bytes and call the callback with the number of bytes which were written.
	/// - parameter bytes: The array of UInt8 to write.
	/// - parameter completion: The callback which will be called once the write has completed. The callback will be passed the number of bytes which were successfuly written, which may be zero.
	public func write(bytes: [UInt8], to: NetAddress, timeoutSeconds: Double, completion: @escaping (() throws -> (Int, NetAddress)) -> ()) {
		var addr = to.addr
		let addrSize = socklen_t(addr.ss_len)
		let count = bytes.count
		let sent = bytes.withUnsafeBytes { ptr in
			withUnsafeBytes(of: &addr) { addrPtr in
				sendto(fd.fd, ptr.baseAddress, count, 0, addrPtr.bindMemory(to: sockaddr.self).baseAddress, addrSize)
			}
		}
		if sent == bytes.count {
			completion({ return (sent, to) })
		} else if isEAgain(err: sent) && timeoutSeconds > 0 {
			NetEvent.add(socket: fd.fd, what: .write, timeoutSeconds: timeoutSeconds) { [weak self] _, w in
				if case .write = w {
					self?.write(bytes: bytes, to: to, timeoutSeconds: 0.0, completion: completion)
				} else {
					completion({
						let err = EAGAIN
						let msg = String(validatingUTF8: strerror(err))!
						throw PerfectNetError.networkError(err, msg + " \(#file) \(#function) \(#line)")

					})
				}
			}
		} else {
			let err = errno
			completion({
				let msg = String(validatingUTF8: strerror(err))!
				throw PerfectNetError.networkError(err, msg + " \(sent) \(#file) \(#function) \(#line)")
			})
		}
	}
}
