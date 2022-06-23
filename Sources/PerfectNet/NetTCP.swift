//
//  NetTCP.swift
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

#if os(Linux)
import SwiftGlibc
let INADDR_NONE = UInt32.max
let EINPROGRESS = Int32(115)
#else
import Darwin
#endif

/// Provides an asynchronous IO wrapper around a file descriptor.
/// Fully realized for TCP socket types but can also serve as a base for sockets from other families, such as with `NetNamedPipe`/AF_UNIX.
public class NetTCP: Net {

	private var networkFailure: Bool = false
	private let reasonableMaxReadCount = 1024 * 600 // <700k is empirically the largest chuck I was reading at a go

	/// Creates an instance which will use the given file descriptor
	/// - parameter fd: The pre-existing file descriptor
	public convenience init(fd: Int32) {
		self.init()
		self.fd.fd = fd
		self.fd.family = AF_INET
		self.fd.switchToNonBlocking()
	}

	public override func initSocket(family: Int32) {
		#if os(Linux)
		initSocket(family: family, type: 1)
		#else
		initSocket(family: family, type: SOCK_STREAM)
		#endif
	}
    // swiftlint:disable syntactic_sugar
	public var localAddress: NetAddress? {
		var addr = Array<Int8>(repeating: 0, count: MemoryLayout<sockaddr_storage>.size)
		var len = socklen_t(MemoryLayout<sockaddr_storage>.size)
		return addr.withUnsafeMutableBytes {
			guard 0 == getsockname(fd.fd, $0.bindMemory(to: sockaddr.self).baseAddress, &len) else {
				return nil
			}
			guard let p = $0.bindMemory(to: sockaddr_storage.self).baseAddress else {
				return nil
			}
			return NetAddress(addr: p.pointee)
		}
	}
    // swiftlint:disable syntactic_sugar
	public var remoteAddress: NetAddress? {
		var addr = Array<Int8>(repeating: 0, count: MemoryLayout<sockaddr_storage>.size)
		var len = socklen_t(MemoryLayout<sockaddr_storage>.size)
		return addr.withUnsafeMutableBytes {
			guard 0 == getpeername(fd.fd, $0.bindMemory(to: sockaddr.self).baseAddress, &len) else {
				return nil
			}
			guard let p = $0.bindMemory(to: sockaddr_storage.self).baseAddress else {
				return nil
			}
			return NetAddress(addr: p.pointee)
		}
	}

	func recv(into buf: UnsafeMutableRawPointer, count: Int) -> Int {
	#if os(Linux)
		return SwiftGlibc.recv(fd.fd, buf, count, 0)
	#else
		return Darwin.recv(fd.fd, buf, count, 0)
	#endif
	}

	func send(_ buf: [UInt8], offsetBy: Int, count: Int) -> Int {
		return buf.withUnsafeBytes { (p: UnsafeRawBufferPointer) -> Int in
			let ptr = p.baseAddress?.advanced(by: offsetBy)
		#if os(Linux)
			return SwiftGlibc.send(fd.fd, ptr, count, 0)
		#else
			return Darwin.send(fd.fd, ptr, count, 0)
		#endif
		}
	}

	private final func completeArray(from frm: ReferenceBuffer, count: Int) -> [UInt8] {
		frm.a.removeLast(frm.size - count)
		return frm.a
	}

	func readBytesFully(into buffer: ReferenceBuffer, read: Int, remaining: Int, timeoutSeconds: Double, completion: @escaping ([UInt8]?) -> ()) {
		let readCount: Int = buffer.withUnsafeMutableBytes(advanced: read) {
			guard let ptr = $0 else {
				return 0
			}
			return recv(into: ptr, count: remaining)
		}
		if readCount == 0 {
			completion(nil) // disconnect
		} else if isEAgain(err: readCount) {
			// no data available. wait
			readBytesFullyIncomplete(into: buffer, read: read, remaining: remaining, timeoutSeconds: timeoutSeconds, completion: completion)
		} else if readCount < 0 {
			completion(nil) // networking or other error
		} else if remaining - readCount == 0 { // done
			completion(completeArray(from: buffer, count: read + readCount))
		} else { // try again for more
			readBytesFully(into: buffer, read: read + readCount, remaining: remaining - readCount, timeoutSeconds: timeoutSeconds, completion: completion)
		}
	}

	func readBytesFullyIncomplete(into to: ReferenceBuffer, read: Int, remaining: Int, timeoutSeconds: Double, completion: @escaping ([UInt8]?) -> ()) {
		NetEvent.add(socket: fd.fd, what: .read, timeoutSeconds: timeoutSeconds) { [weak self] _, w in
			if case .read = w {
				self?.readBytesFully(into: to, read: read, remaining: remaining, timeoutSeconds: timeoutSeconds, completion: completion)
			} else if case .timer = w {
				completion([]) // timeout
			} else {
				completion(nil) // error
			}
		}
	}

	/// Read the indicated number of bytes and deliver them on the provided callback.
	/// - parameter count: The number of bytes to read
	/// - parameter timeoutSeconds: The number of seconds to wait for the requested number of bytes. A timeout value of negative one indicates that the request should have no timeout.
	/// - parameter completion: The callback on which the results will be delivered.
	///		If the timeout occurs before the requested number of bytes have been read, an empty array will be delivered to the callback.
	///		If an error or disconnection occurs then a nil object will be delivered to the callback.
	public func readBytesFully(count cnt: Int, timeoutSeconds: Double, completion: @escaping ([UInt8]?) -> ()) {
		let ptr = ReferenceBuffer(size: cnt)
		readBytesFully(into: ptr, read: 0, remaining: cnt, timeoutSeconds: timeoutSeconds, completion: completion)
	}

	/// Read up to the indicated number of bytes and deliver them on the provided callback.
	/// - parameter count: The maximum number of bytes to read.
	/// - parameter completion: The callback on which to deliver the results.
	///		If an error occurs during the read then a nil object will be passed to the callback, otherwise, the immediately available number of bytes, which may be zero, will be passed.
	public func readSomeBytes(count cnt: Int, completion: @escaping ([UInt8]?) -> ()) {
		let readRead = min(cnt, reasonableMaxReadCount)
		let ptr = ReferenceBuffer(size: readRead)
		let readCount: Int = ptr.withUnsafeMutableBytes(advanced: 0) {
			guard let ptr = $0 else {
				return 0
			}
			return recv(into: ptr, count: readRead)
		}
		if readCount == 0 {
			completion(nil)
		} else if isEAgain(err: readCount) {
			completion([])
		} else if readCount == -1 {
			completion(nil)
		} else {
			let complete = completeArray(from: ptr, count: readCount)
			completion(complete)
		}
	}

	/// Write the string and call the callback with the number of bytes which were written.
	/// - parameter s: The string to write. The string will be written based on its UTF-8 encoding.
	/// - parameter completion: The callback which will be called once the write has completed. The callback will be passed the number of bytes which were successfuly written, which may be zero.
	public func write(string strng: String, completion: @escaping (Int) -> ()) {
		write(bytes: [UInt8](strng.utf8), completion: completion)
	}

	/// Write the indicated bytes and call the callback with the number of bytes which were written.
	/// - parameter bytes: The array of UInt8 to write.
	/// - parameter completion: The callback which will be called once the write has completed. The callback will be passed the number of bytes which were successfuly written, which may be zero.
	public func write(bytes byts: [UInt8], completion: @escaping (Int) -> ()) {
		write(bytes: byts, offsetBy: 0, count: byts.count, completion: completion)
	}

	/// Write the indicated bytes and return true if all data was sent.
	/// - parameter bytes: The array of UInt8 to write.
	public func writeFully(bytes byts: [UInt8]) -> Bool {
		let length = byts.count
		var totalSent = 0
		var s: Threading.Event?
		var what: NetEvent.Filter = .none
		let waitFunc = {
			NetEvent.add(socket: self.fd.fd, what: .write, timeoutSeconds: NetEvent.noTimeout) { _, w in
				what = w
				_ = s?.lock()
				_ = s?.signal()
				_ = s?.unlock()
			}
		}
		while length > 0 {
			let sent = send(byts, offsetBy: totalSent, count: length - totalSent)
			if sent == length {
				return true
			}
			if s == nil {
				s = Threading.Event()
			}
			if sent == -1 {
				if isEAgain(err: sent) { // flow
					_ = s!.lock()
					waitFunc()
				} else { // error
					break
				}
			} else {
				totalSent += sent

				if totalSent == length {
					return true
				}
				_ = s!.lock()
				waitFunc()
			}
			_ = s!.wait()
			_ = s!.unlock()
			if case .write = what {

			} else {
				break
			}
		}
		return totalSent == length
	}

	/// Write the indicated bytes and call the callback with the number of bytes which were written.
	/// - parameter bytes: The array of UInt8 to write.
	/// - parameter offsetBy: The offset within `bytes` at which to begin writing.
	/// - parameter count: The number of bytes to write.
	/// - parameter completion: The callback which will be called once the write has completed. The callback will be passed the number of bytes which were successfuly written, which may be zero.
	public func write(bytes: [UInt8], offsetBy: Int, count: Int, completion: @escaping (Int) -> ()) {
		let sent = send(bytes, offsetBy: offsetBy, count: count)
		if isEAgain(err: sent) {
			writeIncomplete(bytes: bytes, offsetBy: offsetBy, count: count, completion: completion)
		} else if sent == -1 {
			completion(sent)
		} else if sent < count {
			// flow control
			writeIncomplete(bytes: bytes, offsetBy: offsetBy + sent, count: count - sent, completion: completion)
		} else {
			completion(offsetBy + sent)
		}
	}

	func writeIncomplete(bytes: [UInt8], offsetBy: Int, count: Int, completion: @escaping (Int) -> ()) {
		NetEvent.add(socket: fd.fd, what: .write, timeoutSeconds: NetEvent.noTimeout) { _, _ in
			self.write(bytes: bytes, offsetBy: offsetBy, count: count, completion: completion)
		}
	}

	/// Connect to the indicated server
	/// - parameter address: The server's address, expressed as a string.
	/// - parameter port: The port on which to connect.
	/// - parameter timeoutSeconds: The number of seconds to wait for the connection to complete. A timeout of negative one indicates that there is no timeout.
	/// - parameter callBack: The closure which will be called when the connection completes. If the connection completes successfully then the current NetTCP instance will be passed to the callback, otherwise, a nil object will be passed.
	/// - returns: `PerfectError.NetworkError`
	public func connect(address addrs: String, port: UInt16, timeoutSeconds: Double, callBack: @escaping (NetTCP?) -> ()) throws {
		guard var addr = NetAddress(host: addrs, port: port)?.addr else {
			try ThrowNetworkError()
		}
		initSocket(family: Int32(addr.ss_family))
		let len = socklen_t(addr.ss_len)
		let cRes: Int32 = withUnsafeBytes(of: &addr) {
			let saddr = $0.bindMemory(to: sockaddr.self).baseAddress
		#if os(Linux)
			return SwiftGlibc.connect(self.fd.fd, saddr, len)
		#else
			return Darwin.connect(self.fd.fd, saddr, len)
		#endif
		}
		if cRes != -1 {
			callBack(self)
		} else {
			guard errno == EINPROGRESS else {
				try ThrowNetworkError()
			}
			NetEvent.add(socket: fd.fd, what: .write, timeoutSeconds: timeoutSeconds) { _, w in
				if case .timer = w {
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
	public func accept(timeoutSeconds timeout: Double, callBack: @escaping (NetTCP?) -> ()) throws {
	#if os(Linux)
		let accRes = SwiftGlibc.accept(fd.fd, nil, nil)
	#else
		let accRes = Darwin.accept(fd.fd, nil, nil)
	#endif
		if accRes != -1 {
			let newTcp = makeFromFd(accRes)
			return callBack(newTcp)
		}
        guard isEAgain(err: Int(accRes)) else {
            try ThrowNetworkError()
        }
        NetEvent.add(socket: fd.fd, what: .read, timeoutSeconds: timeout) { _, w in
            if case .timer = w {
                return callBack(nil)
            }
            do {
                try self.accept(timeoutSeconds: timeout, callBack: callBack)
            } catch {
                callBack(nil)
            }
        }
	}

	private func tryAccept() -> Int32 {
    #if os(Linux)
        let accRes = SwiftGlibc.accept(fd.fd, nil, nil)
    #else
        let accRes = Darwin.accept(fd.fd, nil, nil)
    #endif
		return accRes
	}

	/// Accept a series of new client connections and pass them to the callback. This function does not return outside of a catastrophic error.
	/// - parameter callBack: The closure which will be called when the accept completes. the parameter will be a newly allocated instance of NetTCP which represents the client.
	public func forEachAccept(callBack: @escaping (NetTCP?) -> ()) {
		fd.switchToBlocking()
		repeat {
			let accRes = tryAccept()
			if accRes != -1 {
				netHandleQueue.async {
					callBack(self.makeFromFd(accRes))
				}
			} else if errno != EINTR {
				let errStr = String(validatingUTF8: strerror(Int32(errno))) ?? "NO MESSAGE"
				print("Unexpected networking error: \(errno) '\(errStr)'")
				networkFailure = true
			}
		} while !networkFailure && fd.fd != invalidSocket
	}

	func makeFromFd(_ fd: Int32) -> NetTCP {
		return NetTCP(fd: fd)
	}
}
