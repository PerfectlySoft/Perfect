//
//  NetNamedPipe.swift
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
	let AF_UNIX: Int32 = 1
	let SOL_SOCKET: Int32 = 1
	let SCM_RIGHTS: Int32 = 0x01
	#else
	import Darwin
#endif

/// This sub-class of NetTCP handles networking over an AF_UNIX named pipe connection.
public class NetNamedPipe : NetTCP {

	/// Initialize the object using an existing file descriptor.
	public convenience init(fd: Int32) {
		self.init()
		self.fd.fd = fd
		self.fd.family = AF_UNIX
		self.fd.switchToNBIO()
	}

	/// Override socket initialization to handle the UNIX socket type.
	public override func initSocket() {
	#if os(Linux)
		fd.fd = socket(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0)
	#else
		fd.fd = socket(AF_UNIX, SOCK_STREAM, 0)
	#endif
		fd.family = AF_UNIX
		fd.switchToNBIO()
	}

	public override func sockName() -> (String, UInt16) {
		var addr = UnsafeMutablePointer<sockaddr_un>.allocatingCapacity(1)
		var len = UnsafeMutablePointer<socklen_t>.allocatingCapacity(1)
		defer {
			addr.deallocateCapacity(1)
			len.deallocateCapacity(1)
		}
		len.pointee = socklen_t(sizeof(sockaddr_in))
		getsockname(fd.fd, UnsafeMutablePointer<sockaddr>(addr), len)

		var nameBuf = [CChar]()
		let mirror = Mirror(reflecting: addr.pointee.sun_path)
	#if swift(>=3.0)
		let childGen = mirror.children.makeIterator()
	#else
		let childGen = mirror.children.generate()
	#endif
		for _ in 0..<1024 {
			let (_, elem) = childGen.next()!
			if (elem as! Int8) == 0 {
				break
			}
			nameBuf.append(elem as! Int8)
		}
		nameBuf.append(0)
		let s = String(validatingUTF8: nameBuf) ?? ""
		let p = UInt16(0)

		return (s, p)
	}

	public override func peerName() -> (String, UInt16) {
		var addr = UnsafeMutablePointer<sockaddr_un>.allocatingCapacity(1)
		var len = UnsafeMutablePointer<socklen_t>.allocatingCapacity(1)
		defer {
			addr.deallocateCapacity(1)
			len.deallocateCapacity(1)
		}
		len.pointee = socklen_t(sizeof(sockaddr_in))
		getpeername(fd.fd, UnsafeMutablePointer<sockaddr>(addr), len)

		var nameBuf = [CChar]()
		let mirror = Mirror(reflecting: addr.pointee.sun_path)
	#if swift(>=3.0)
		let childGen = mirror.children.makeIterator()
	#else
		let childGen = mirror.children.generate()
	#endif
		for _ in 0..<1024 {
			let (_, elem) = childGen.next()!
			if (elem as! Int8) == 0 {
				break
			}
			nameBuf.append(elem as! Int8)
		}
		nameBuf.append(0)
		let s = String(validatingUTF8: nameBuf) ?? ""
		let p = UInt16(0)

		return (s, p)
	}

	/// Bind the socket to the address path
	/// - parameter address: The path on the file system at which to create and bind the socket
	/// - throws: `PerfectError.NetworkError`
	public func bind(address address: String) throws {

		initSocket()

		let utf8 = address.utf8
#if os(Linux) // BSDs have a size identifier in front, Linux does not
		let addrLen = sizeof(sockaddr_un)
#else
		let addrLen = sizeof(UInt8) + sizeof(sa_family_t) + utf8.count + 1
#endif
		let addrPtr = UnsafeMutablePointer<UInt8>.allocatingCapacity(addrLen)
		defer { addrPtr.deallocateCapacity(addrLen) }

		var memLoc = 0

#if os(Linux) // BSDs use one byte for sa_family_t, Linux uses two
		let afUnixShort = UInt16(AF_UNIX)
		addrPtr[memLoc] = UInt8(afUnixShort & 0xFF)
		memLoc += 1
		addrPtr[memLoc] = UInt8((afUnixShort >> 8) & 0xFF)
		memLoc += 1
#else
		addrPtr[memLoc] = UInt8(addrLen)
		memLoc += 1
		addrPtr[memLoc] = UInt8(AF_UNIX)
		memLoc += 1
#endif

		for char in utf8 {
			addrPtr[memLoc] = char
			memLoc += 1
		}

		addrPtr[memLoc] = 0
	#if os(Linux)
		let bRes = SwiftGlibc.bind(fd.fd, UnsafePointer<sockaddr>(addrPtr), socklen_t(addrLen))
		#else
		let bRes = Darwin.bind(fd.fd, UnsafePointer<sockaddr>(addrPtr), socklen_t(addrLen))
	#endif
		if bRes == -1 {
			throw PerfectError.NetworkError(errno, String(validatingUTF8: strerror(errno))!)
		}
	}

	/// Connect to the indicated server socket
	/// - parameter address: The server socket file.
	/// - parameter timeoutSeconds: The number of seconds to wait for the connection to complete. A timeout of negative one indicates that there is no timeout.
	/// - parameter callBack: The closure which will be called when the connection completes. If the connection completes successfully then the current NetNamedPipe instance will be passed to the callback, otherwise, a nil object will be passed.
	/// - returns: `PerfectError.NetworkError`
	public func connect(address address: String, timeoutSeconds: Double, callBack: (NetNamedPipe?) -> ()) throws {

		initSocket()

		let utf8 = address.utf8
		let addrLen = sizeof(UInt8) + sizeof(sa_family_t) + utf8.count + 1
		let addrPtr = UnsafeMutablePointer<UInt8>.allocatingCapacity(addrLen)

		defer { addrPtr.deallocateCapacity(addrLen) }

		var memLoc = 0

		addrPtr[memLoc] = UInt8(addrLen)
                memLoc += 1
		addrPtr[memLoc] = UInt8(AF_UNIX)
                memLoc += 1

		for char in utf8 {
			addrPtr[memLoc] = char
			memLoc += 1
		}

		addrPtr[memLoc] = 0
	#if os(Linux)
		let cRes = SwiftGlibc.connect(fd.fd, UnsafePointer<sockaddr>(addrPtr), socklen_t(addrLen))
	#else
		let cRes = Darwin.connect(fd.fd, UnsafePointer<sockaddr>(addrPtr), socklen_t(addrLen))
	#endif
		if cRes != -1 {
			callBack(self)
		} else {
			guard errno == EINPROGRESS else {
				try ThrowNetworkError()
			}

			NetEvent.add(socket: fd.fd, what: .Write, timeoutSeconds: timeoutSeconds) {
				fd, w in
			
				if case .Timer = w {
					callBack(nil)
				} else {
					callBack(self)
				}
			}
		}
	}

	/// Send the existing opened file descriptor over the connection to the recipient
	/// - parameter fd: The file descriptor to send
	/// - parameter callBack: The callback to call when the send completes. The parameter passed will be `true` if the send completed without error.
	/// - throws: `PerfectError.NetworkError`
	public func sendFd(_ fd: Int32, callBack: (Bool) -> ()) throws {
		let length = sizeof(cmsghdr) + sizeof(Int32)
	#if os(Linux)
		var msghdr = UnsafeMutablePointer<SwiftGlibc.msghdr>.allocatingCapacity(1)
	#else
		var msghdr = UnsafeMutablePointer<Darwin.msghdr>.allocatingCapacity(1)
	#endif
		var nothingPtr = UnsafeMutablePointer<iovec>.allocatingCapacity(1)
		var nothing = UnsafeMutablePointer<CChar>.allocatingCapacity(1)
		let buffer = UnsafeMutablePointer<CChar>.allocatingCapacity(length)
		defer {
			msghdr.deallocateCapacity(1)
			buffer.deallocateCapacity(length)
			nothingPtr.deallocateCapacity(1)
			nothing.deallocateCapacity(1)
		}

		var cmsg = UnsafeMutablePointer<cmsghdr>(buffer)
	#if os(Linux)
		cmsg.pointee.cmsg_len = Int(socklen_t(length))
	#else
		cmsg.pointee.cmsg_len = socklen_t(length)
	#endif
		cmsg.pointee.cmsg_level = SOL_SOCKET
		cmsg.pointee.cmsg_type = SCM_RIGHTS
		// swift 2.2 compat
		var asInts = UnsafeMutablePointer<Int32>(cmsg.advanced(by: 1))
		asInts.pointee = fd

		nothing.pointee = 33

		nothingPtr.pointee.iov_base = UnsafeMutablePointer<Void>(nothing)
		nothingPtr.pointee.iov_len = 1

		msghdr.pointee.msg_name = UnsafeMutablePointer<Void>(nil)
		msghdr.pointee.msg_namelen = 0
		msghdr.pointee.msg_flags = 0
		msghdr.pointee.msg_iov = nothingPtr
		msghdr.pointee.msg_iovlen = 1
		msghdr.pointee.msg_control = UnsafeMutablePointer<Void>(buffer)
	#if os(Linux)
		msghdr.pointee.msg_controllen = Int(socklen_t(length))
	#else
		msghdr.pointee.msg_controllen = socklen_t(length)
	#endif

		let res = sendmsg(Int32(self.fd.fd), msghdr, 0)
		if res > 0 {
			callBack(true)
		} else if res == -1 && errno == EAGAIN {

			NetEvent.add(socket: self.fd.fd, what: .Write, timeoutSeconds: NetEvent.noTimeout) { [weak self]
				fd, w in
			
				do {
					try self?.sendFd(fd, callBack: callBack)
				} catch {
					callBack(false)
				}
			}

		} else {
			try ThrowNetworkError()
		}
	}

	/// Receive an existing opened file descriptor from the sender
	/// - parameter callBack: The callback to call when the receive completes. The parameter passed will be the received file descriptor or invalidSocket.
	/// - throws: `PerfectError.NetworkError`
	public func receiveFd(callBack cb: (Int32) -> ()) throws {
		let length = sizeof(cmsghdr) + sizeof(Int32)
		var msghdrr = msghdr()
		var nothingPtr = UnsafeMutablePointer<iovec>.allocatingCapacity(1)
		var nothing = UnsafeMutablePointer<CChar>.allocatingCapacity(1)
		let buffer = UnsafeMutablePointer<CChar>.allocatingCapacity(length)
		defer {
			buffer.deallocateCapacity(length)
			nothingPtr.deallocateCapacity(1)
			nothing.deallocateCapacity(1)
		}

		nothing.pointee = 33

		nothingPtr.pointee.iov_base = UnsafeMutablePointer<Void>(nothing)
		nothingPtr.pointee.iov_len = 1

		msghdrr.msg_iov = UnsafeMutablePointer<iovec>(nothingPtr)
		msghdrr.msg_iovlen = 1
		msghdrr.msg_control = UnsafeMutablePointer<Void>(buffer)
	#if os(Linux)
		msghdrr.msg_controllen = Int(socklen_t(length))
	#else
		msghdrr.msg_controllen = socklen_t(length)
	#endif

		var cmsg = UnsafeMutablePointer<cmsghdr>(buffer)
	#if os(Linux)
		cmsg.pointee.cmsg_len = Int(socklen_t(length))
	#else
		cmsg.pointee.cmsg_len = socklen_t(length)
	#endif
		cmsg.pointee.cmsg_level = SOL_SOCKET
		cmsg.pointee.cmsg_type = SCM_RIGHTS
		// swift 2.2 compat
		var asInts = UnsafeMutablePointer<Int32>(cmsg.advanced(by: 1))
		asInts.pointee = -1

		let res = recvmsg(Int32(self.fd.fd), &msghdrr, 0)
		if res > 0 {
			let receivedInt = asInts.pointee
			cb(receivedInt)
		} else if res == -1 && errno == EAGAIN {

			NetEvent.add(socket: self.fd.fd, what: .Read, timeoutSeconds: NetEvent.noTimeout) { [weak self]
				fd, w in
			
				do {
					try self?.receiveFd(callBack: cb)
				} catch {
					cb(invalidSocket)
				}
			}

		} else {
			try ThrowNetworkError()
		}

	}

	/// Send the existing & opened `File`'s descriptor over the connection to the recipient
	/// - parameter file: The `File` whose descriptor to send
	/// - parameter callBack: The callback to call when the send completes. The parameter passed will be `true` if the send completed without error.
	/// - throws: `PerfectError.NetworkError`
	public func sendFile(_ file: File, callBack: (Bool) -> ()) throws {
		try self.sendFd(Int32(file.fd), callBack: callBack)
	}

	/// Send the existing & opened `NetTCP`'s descriptor over the connection to the recipient
	/// - parameter file: The `NetTCP` whose descriptor to send
	/// - parameter callBack: The callback to call when the send completes. The parameter passed will be `true` if the send completed without error.
	/// - throws: `PerfectError.NetworkError`
	public func sendFile(_ file: NetTCP, callBack: (Bool) -> ()) throws {
		try self.sendFd(file.fd.fd, callBack: callBack)
	}

	/// Receive an existing opened `File` descriptor from the sender
	/// - parameter callBack: The callback to call when the receive completes. The parameter passed will be the received `File` object or nil.
	/// - throws: `PerfectError.NetworkError`
	public func receiveFile(callBack: (File?) -> ()) throws {
		try self.receiveFd {
			(fd: Int32) -> () in

			if fd == invalidSocket {
				callBack(nil)
			} else {
				callBack(File(fd: fd, path: ""))
			}
		}
	}

	/// Receive an existing opened `NetTCP` descriptor from the sender
	/// - parameter callBack: The callback to call when the receive completes. The parameter passed will be the received `NetTCP` object or nil.
	/// - throws: `PerfectError.NetworkError`
	public func receiveNetTCP(callBack: (NetTCP?) -> ()) throws {
		try self.receiveFd {
			(fd: Int32) -> () in

			if fd == invalidSocket {
				callBack(nil)
			} else {
				callBack(NetTCP(fd: fd))
			}
		}
	}

	/// Receive an existing opened `NetNamedPipe` descriptor from the sender
	/// - parameter callBack: The callback to call when the receive completes. The parameter passed will be the received `NetNamedPipe` object or nil.
	/// - throws: `PerfectError.NetworkError`
	public func receiveNetNamedPipe(callBack: (NetNamedPipe?) -> ()) throws {
		try self.receiveFd {
			(fd: Int32) -> () in

			if fd == invalidSocket {
				callBack(nil)
			} else {
				callBack(NetNamedPipe(fd: fd))
			}
		}
	}

	override func makeFromFd(_ fd: Int32) -> NetTCP {
		return NetNamedPipe(fd: fd)
	}
}
