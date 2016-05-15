//
//  NetTCP.swift
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
let AF_UNSPEC: Int32 = 0
let AF_INET: Int32 = 2
let INADDR_NONE = UInt32(0xffffffff)
let EINPROGRESS = Int32(115)
#else
import Darwin
#endif

/// Provides an asynchronous IO wrapper around a file descriptor.
/// Fully realized for TCP socket types but can also serve as a base for sockets from other families, such as with `NetNamedPipe`/AF_UNIX.
public class NetTCP : Closeable {
	
	private var networkFailure: Bool = false
	private var semaphore: Threading.Event?
	
	class ReferenceBuffer {
		var b: UnsafeMutablePointer<UInt8>
		let size: Int
		init(size: Int) {
			self.size = size
			self.b = UnsafeMutablePointer<UInt8>.allocatingCapacity(size)
		}
		
		deinit {
			self.b.deallocateCapacity(self.size)
		}
	}
	
	var fd: SocketFileDescriptor = SocketFileDescriptor(fd: invalidSocket, family: AF_UNSPEC)
	
	/// Create a new object with an initially invalid socket file descriptor.
	public init() {
		
	}
	
	/// Creates an instance which will use the given file descriptor
	/// - parameter fd: The pre-existing file descriptor
	public convenience init(fd: Int32) {
		self.init()
		self.fd.fd = fd
		self.fd.family = AF_INET
		self.fd.switchToNBIO()
	}
	
	/// Allocates a new socket if it has not already been done.
	/// The functions `bind` and `connect` will call this method to ensure the socket has been allocated.
	/// Sub-classes should override this function in order to create their specialized socket.
	/// All sub-class sockets should be switched to utilize non-blocking IO by calling `SocketFileDescriptor.switchToNBIO()`.
	public func initSocket() {
		if fd.fd == invalidSocket {
		#if os(Linux)
			fd.fd = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
		#else
			fd.fd = socket(AF_INET, SOCK_STREAM, 0)
		#endif
			fd.family = AF_INET
			fd.switchToNBIO()
		}
	}
	
	public func sockName() -> (String, UInt16) {
		let staticBufferSize = 1024
		var addr = UnsafeMutablePointer<sockaddr_in>.allocatingCapacity(1)
		var len = UnsafeMutablePointer<socklen_t>.allocatingCapacity(1)
		let buffer = UnsafeMutablePointer<Int8>.allocatingCapacity(staticBufferSize)
		defer {
			addr.deallocateCapacity(1)
			len.deallocateCapacity(1)
			buffer.deallocateCapacity(staticBufferSize)
		}
		len.pointee = socklen_t(sizeof(sockaddr_in))
		getsockname(fd.fd, UnsafeMutablePointer<sockaddr>(addr), len)
		inet_ntop(fd.family, &addr.pointee.sin_addr, buffer, len.pointee)
		
		let s = String(validatingUTF8: buffer) ?? ""
		let p = ntohs(addr.pointee.sin_port)
		
		return (s, p)
	}
	
	public func peerName() -> (String, UInt16) {
		let staticBufferSize = 1024
		var addr = UnsafeMutablePointer<sockaddr_in>.allocatingCapacity(1)
		var len = UnsafeMutablePointer<socklen_t>.allocatingCapacity(1)
		let buffer = UnsafeMutablePointer<Int8>.allocatingCapacity(staticBufferSize)
		defer {
			addr.deallocateCapacity(1)
			len.deallocateCapacity(1)
			buffer.deallocateCapacity(staticBufferSize)
		}
		len.pointee = socklen_t(sizeof(sockaddr_in))
		getpeername(fd.fd, UnsafeMutablePointer<sockaddr>(addr), len)
		inet_ntop(fd.family, &addr.pointee.sin_addr, buffer, len.pointee)
		
		let s = String(validatingUTF8: buffer) ?? ""
		let p = ntohs(addr.pointee.sin_port)
		
		return (s, p)
	}
	
	func isEAgain(err er: Int) -> Bool {
		return er == -1 && errno == EAGAIN
	}
	
	/// Bind the socket on the given port and optional local address
	/// - parameter port: The port on which to bind
	/// - parameter address: The the local address, given as a string, on which to bind. Defaults to "0.0.0.0".
	/// - throws: PerfectError.NetworkError
	public func bind(port prt: UInt16, address: String = "0.0.0.0") throws {
		
		initSocket()
		
		var addr: sockaddr_in = sockaddr_in()
		let res = makeAddress(&addr, host: address, port: prt)
		guard res != -1 else {
			try ThrowNetworkError()
		}
		let i0 = Int8(0)
	#if os(Linux)
		var sock_addr = sockaddr(sa_family: 0, sa_data: (i0, i0, i0, i0, i0, i0, i0, i0, i0, i0, i0, i0, i0, i0))
	#else
		var sock_addr = sockaddr(sa_len: 0, sa_family: 0, sa_data: (i0, i0, i0, i0, i0, i0, i0, i0, i0, i0, i0, i0, i0, i0))
	#endif
		memcpy(&sock_addr, &addr, Int(sizeof(sockaddr_in)))
	#if os(Linux)
		let bRes = SwiftGlibc.bind(fd.fd, &sock_addr, socklen_t(sizeof(sockaddr_in)))
	#else
		let bRes = Darwin.bind(fd.fd, &sock_addr, socklen_t(sizeof(sockaddr_in)))
	#endif
		if bRes == -1 {
			try ThrowNetworkError()
		}
	}
	
	/// Switches the socket to server mode. Socket should have been previously bound using the `bind` function.
	public func listen(backlog: Int32 = 128) {
	#if os(Linux)
		SwiftGlibc.listen(fd.fd, backlog)
	#else
		Darwin.listen(fd.fd, backlog)
	#endif
	}
	
	/// Shuts down and closes the socket.
	/// The object may be reused.
	public func close() {
		if fd.fd != invalidSocket {
		#if os(Linux)
			shutdown(fd.fd, 2) // !FIX!
			SwiftGlibc.close(fd.fd)
		#else
			shutdown(fd.fd, SHUT_RDWR)
			Darwin.close(fd.fd)
		#endif
			
			fd.fd = invalidSocket
			
			if self.semaphore != nil {
				self.semaphore!.lock()
				self.semaphore!.signal()
				self.semaphore!.unlock()
			}
		}
	}
	
	func recv(into buf: UnsafeMutablePointer<Void>, count: Int) -> Int {
	#if os(Linux)
		return SwiftGlibc.recv(self.fd.fd, buf, count, 0)
	#else
		return Darwin.recv(self.fd.fd, buf, count, 0)
	#endif
	}
	
	func send(_ buf: UnsafePointer<Void>, count: Int) -> Int {
	#if os(Linux)
		return SwiftGlibc.send(self.fd.fd, buf, count, 0)
	#else
		return Darwin.send(self.fd.fd, buf, count, 0)
	#endif
	}

	#if swift(>=3.0)
	private func makeAddress(_ sin: inout sockaddr_in, host: String, port: UInt16) -> Int {
		
		let bPort = port.bigEndian
		sin.sin_port = in_port_t(bPort)
		sin.sin_family = sa_family_t(AF_INET)
		
		defer {
			endhostent()
		}
		
		if let theHost: UnsafeMutablePointer<hostent> = gethostbyname(host), firstAddress = theHost.pointee.h_addr_list.pointee {
			sin.sin_addr.s_addr = UnsafeMutablePointer<UInt32>(firstAddress).pointee
		} else {
			if inet_addr(host) == INADDR_NONE {
				endhostent()
				return -1
			}
			sin.sin_addr.s_addr = inet_addr(host)
		}
		
		return 0
	}
	#else
	private func makeAddress(inout sin: sockaddr_in, host: String, port: UInt16) -> Int {
		let theHost: UnsafeMutablePointer<hostent> = gethostbyname(host)
		if theHost == nil {
			if inet_addr(host) == INADDR_NONE {
				endhostent()
				return -1
			}
		}
		let bPort = port.bigEndian
		sin.sin_port = in_port_t(bPort)
		sin.sin_family = sa_family_t(AF_INET)
		if theHost != nil {
			sin.sin_addr.s_addr = UnsafeMutablePointer<UInt32>(theHost.pointee.h_addr_list.pointee).pointee
		} else {
			sin.sin_addr.s_addr = inet_addr(host)
		}
		endhostent()
		return 0
	}
	#endif
	
	private func completeArray(from frm: ReferenceBuffer, count: Int) -> [UInt8] {
		
		var ary = [UInt8](repeating: 0, count: count)
		for index in 0..<count {
			ary[index] = frm.b[index]
		}
		return ary
	}
	
	func readBytesFully(into int: ReferenceBuffer, read: Int, remaining: Int, timeoutSeconds: Double, completion: ([UInt8]?) -> ()) {
		let readCount = recv(into: int.b + read, count: remaining)
		if readCount == 0 {
			completion(nil) // disconnect
		} else if self.isEAgain(err: readCount) {
			
			// no data available. wait
			self.readBytesFullyIncomplete(into: int, read: read, remaining: remaining, timeoutSeconds: timeoutSeconds, completion: completion)
			
		} else if readCount < 0 {
			completion(nil) // networking or other error
		} else {
			
			// got some data
			if remaining - readCount == 0 { // done
				completion(completeArray(from: int, count: read + readCount))
			} else { // try again for more
				readBytesFully(into: int, read: read + readCount, remaining: remaining - readCount, timeoutSeconds: timeoutSeconds, completion: completion)
			}
		}
	}
	
	func readBytesFullyIncomplete(into to: ReferenceBuffer, read: Int, remaining: Int, timeoutSeconds: Double, completion: ([UInt8]?) -> ()) {
		
		NetEvent.add(socket: fd.fd, what: .Read, timeoutSeconds: timeoutSeconds) { [weak self]
			fd, w in
			
			if case .Read = w {
				self?.readBytesFully(into: to, read: read, remaining: remaining, timeoutSeconds: timeoutSeconds, completion: completion)
			} else {
				completion(nil) // timeout or error
			}
		}
	}
	
	/// Read the indicated number of bytes and deliver them on the provided callback.
	/// - parameter count: The number of bytes to read
	/// - parameter timeoutSeconds: The number of seconds to wait for the requested number of bytes. A timeout value of negative one indicates that the request should have no timeout.
	/// - parameter completion: The callback on which the results will be delivered. If the timeout occurs before the requested number of bytes have been read, a nil object will be delivered to the callback.
	public func readBytesFully(count cnt: Int, timeoutSeconds: Double, completion: ([UInt8]?) -> ()) {

		let ptr = ReferenceBuffer(size: cnt)
		readBytesFully(into: ptr, read: 0, remaining: cnt, timeoutSeconds: timeoutSeconds, completion: completion)
	}
	
	/// Read up to the indicated number of bytes and deliver them on the provided callback.
	/// - parameter count: The maximum number of bytes to read.
	/// - parameter completion: The callback on which to deliver the results. If an error occurs during the read then a nil object will be passed to the callback, otherwise, the immediately available number of bytes, which may be zero, will be passed.
	public func readSomeBytes(count cnt: Int, completion: ([UInt8]?) -> ()) {
		
		let ptr = ReferenceBuffer(size: cnt)
		let readCount = recv(into: ptr.b, count: cnt)
		if readCount == 0 {
			completion(nil)
		} else if self.isEAgain(err: readCount) {
			completion([UInt8]())
		} else if readCount == -1 {
			completion(nil)
		} else {
			completion(completeArray(from: ptr, count: readCount))
		}
	}
	
	/// Write the string and call the callback with the number of bytes which were written.
	/// - parameter s: The string to write. The string will be written based on its UTF-8 encoding.
	/// - parameter completion: The callback which will be called once the write has completed. The callback will be passed the number of bytes which were successfuly written, which may be zero.
	public func write(string strng: String, completion: (Int) -> ()) {
		write(bytes: [UInt8](strng.utf8), completion: completion)
	}
	
	/// Write the indicated bytes and call the callback with the number of bytes which were written.
	/// - parameter bytes: The array of UInt8 to write.
	/// - parameter completion: The callback which will be called once the write has completed. The callback will be passed the number of bytes which were successfuly written, which may be zero.
	public func write(bytes byts: [UInt8], completion: (Int) -> ()) {
		write(bytes: byts, dataPosition: 0, length: byts.count, completion: completion)
	}
	
	/// Write the indicated bytes and return true if all data was sent.
	/// - parameter bytes: The array of UInt8 to write.
	public func writeFully(bytes byts: [UInt8]) -> Bool {
		let length = byts.count
		var totalSent = 0
		let ptr = UnsafeMutablePointer<UInt8>(byts)
		var s: Threading.Event?
		var what: NetEvent.Filter = .None
		
		let waitFunc = {
			NetEvent.add(socket: self.fd.fd, what: .Write, timeoutSeconds: 0.0) {
				_, w in
				what = w
				s?.lock()
				s?.signal()
				s?.unlock()
			}
		}
		
		while length > 0 {
			
			let sent = send(ptr.advanced(by: totalSent), count: length - totalSent)
			if sent == length {
				return true
			}
			
			if s == nil {
				s = Threading.Event()
			}
			
			if sent == -1 {
				if isEAgain(err: sent) { // flow
					s!.lock()
					waitFunc()
				} else { // error
					break
				}
			} else {
				totalSent += sent
				
				if totalSent == length {
					return true
				}
				s!.lock()
				waitFunc()
			}
			
			s!.wait()
			s!.unlock()
			if case .Write = what {
			
			} else {
				break
			}
		}
		return totalSent == length
	}
			 
	/// Write the indicated bytes and call the callback with the number of bytes which were written.
	/// - parameter bytes: The array of UInt8 to write.
	/// - parameter dataPosition: The offset within `bytes` at which to begin writing.
	/// - parameter length: The number of bytes to write.
	/// - parameter completion: The callback which will be called once the write has completed. The callback will be passed the number of bytes which were successfuly written, which may be zero.
	public func write(bytes byts: [UInt8], dataPosition: Int, length: Int, completion: (Int) -> ()) {
		
		let ptr = UnsafeMutablePointer<UInt8>(byts).advanced(by: dataPosition)
		write(bytes: ptr, wrote: 0, length: length, completion: completion)
	}
	
	func write(bytes byts: UnsafeMutablePointer<UInt8>, wrote: Int, length: Int, completion: (Int) -> ()) {
		let sent = send(byts, count: length)
		if isEAgain(err: sent) {
			writeIncomplete(bytes: byts, wrote: wrote, length: length, completion: completion)
		} else if sent == -1 {
			completion(sent)
		} else if sent < length {
			// flow control
			writeIncomplete(bytes: byts.advanced(by: sent), wrote: wrote + sent, length: length - sent, completion: completion)
		} else {
			completion(wrote + sent)
		}
	}
	
	func writeIncomplete(bytes nptr: UnsafeMutablePointer<UInt8>, wrote: Int, length: Int, completion: (Int) -> ()) {
		
		NetEvent.add(socket: fd.fd, what: .Write, timeoutSeconds: 0.0) {
			fd, w in
			
			self.write(bytes: nptr, wrote: wrote, length: length, completion: completion)
		}
	}
	
	/// Connect to the indicated server
	/// - parameter address: The server's address, expressed as a string.
	/// - parameter port: The port on which to connect.
	/// - parameter timeoutSeconds: The number of seconds to wait for the connection to complete. A timeout of negative one indicates that there is no timeout.
	/// - parameter callBack: The closure which will be called when the connection completes. If the connection completes successfully then the current NetTCP instance will be passed to the callback, otherwise, a nil object will be passed.
	/// - returns: `PerfectError.NetworkError`
	public func connect(address addrs: String, port: UInt16, timeoutSeconds: Double, callBack: (NetTCP?) -> ()) throws {
		
		initSocket()
		
		var addr: sockaddr_in = sockaddr_in()
		let res = makeAddress(&addr, host: addrs, port: port)
		guard res != -1 else {
			try ThrowNetworkError()
		}
		let i0 = Int8(0)
	#if os(Linux)
		var sock_addr = sockaddr(sa_family: 0, sa_data: (i0, i0, i0, i0, i0, i0, i0, i0, i0, i0, i0, i0, i0, i0))
	#else
		var sock_addr = sockaddr(sa_len: 0, sa_family: 0, sa_data: (i0, i0, i0, i0, i0, i0, i0, i0, i0, i0, i0, i0, i0, i0))
	#endif
		memcpy(&sock_addr, &addr, Int(sizeof(sockaddr_in)))
		
	#if os(Linux)
		let cRes = SwiftGlibc.connect(fd.fd, &sock_addr, socklen_t(sizeof(sockaddr_in)))
	#else
		let cRes = Darwin.connect(fd.fd, &sock_addr, socklen_t(sizeof(sockaddr_in)))
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
	
	/// Accept a new client connection and pass the result to the callback.
	/// - parameter timeoutSeconds: The number of seconds to wait for a new connection to arrive. A timeout value of negative one indicates that there is no timeout.
	/// - parameter callBack: The closure which will be called when the accept completes. the parameter will be a newly allocated instance of NetTCP which represents the client.
	/// - returns: `PerfectError.NetworkError`
	public func accept(timeoutSeconds timeout: Double, callBack: (NetTCP?) -> ()) throws {
	#if os(Linux)
		let accRes = SwiftGlibc.accept(fd.fd, UnsafeMutablePointer<sockaddr>(nil), UnsafeMutablePointer<socklen_t>(nil))
	#else
		let accRes = Darwin.accept(fd.fd, UnsafeMutablePointer<sockaddr>(nil), UnsafeMutablePointer<socklen_t>(nil))
	#endif
		if accRes != -1 {
			let newTcp = self.makeFromFd(accRes)
			callBack(newTcp)
		} else {
			guard self.isEAgain(err: Int(accRes)) else {
				try ThrowNetworkError()
			}
			
			NetEvent.add(socket: fd.fd, what: .Read, timeoutSeconds: timeout) {
				fd, w in
			
				if case .Timer = w {
					callBack(nil)
				} else {
					do {
						try self.accept(timeoutSeconds: timeout, callBack: callBack)
					} catch {
						callBack(nil)
					}
				}
			}
		}
	}
	
	private func tryAccept() -> Int32 {
		#if os(Linux)
			let accRes = SwiftGlibc.accept(fd.fd, UnsafeMutablePointer<sockaddr>(nil), UnsafeMutablePointer<socklen_t>(nil))
		#else
			let accRes = Darwin.accept(fd.fd, UnsafeMutablePointer<sockaddr>(nil), UnsafeMutablePointer<socklen_t>(nil))
		#endif

		return accRes
	}
	
	private func waitAccept() {
		
		NetEvent.add(socket: fd.fd, what: .Read, timeoutSeconds: 0.0) { [weak self]
			_, _ in
			
			self?.semaphore!.lock()
			self?.semaphore!.signal()
			self?.semaphore!.unlock()
		}
	}
	
	/// Accept a series of new client connections and pass them to the callback. This function does not return outside of a catastrophic error.
	/// - parameter callBack: The closure which will be called when the accept completes. the parameter will be a newly allocated instance of NetTCP which represents the client.
	public func forEachAccept(callBack: (NetTCP?) -> ()) {
		
		guard self.semaphore == nil else {
			return
		}
		
		self.semaphore = Threading.Event()
		defer { self.semaphore = nil }
		
		repeat {
		
			let accRes = tryAccept()
			if accRes != -1 {
				Threading.dispatchBlock {
					callBack(self.makeFromFd(accRes))
				}
			} else if self.isEAgain(err: Int(accRes)) {
				self.semaphore!.lock()
				waitAccept()
				self.semaphore!.wait()
				self.semaphore!.unlock()
			} else {
				let errStr = String(validatingUTF8: strerror(Int32(errno))) ?? "NO MESSAGE"
				print("Unexpected networking error: \(errno) '\(errStr)'")
				networkFailure = true
			}
		} while !networkFailure && self.fd.fd != invalidSocket
		return
	}
	
	func makeFromFd(_ fd: Int32) -> NetTCP {
		return NetTCP(fd: fd)
	}
}





