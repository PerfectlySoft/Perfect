//
//  ByteIO.swift
//  PerfectCrypto
//
//  Created by Kyle Jessup on 2017-02-07.
//	Copyright (C) 2017 PerfectlySoft, Inc.
//
// ===----------------------------------------------------------------------===//
//
// This source file is part of the Perfect.org open source project
//
// Copyright (c) 2015 - 2017 PerfectlySoft Inc. and the Perfect project authors
// Licensed under Apache License v2.0
//
// See http://perfect.org/licensing.html for license information
//
// ===----------------------------------------------------------------------===//
//
//

import COpenSSL
#if os(Linux)
	import SwiftGlibc
#else
	import Darwin
#endif
// swiftlint:disable todo
// TODO: SSLFilter
// it needs many options to configure it

/// An object which is used in byte IO operations.
public protocol ByteIO { }

/// An object which supports `put` and `write` operations.
public protocol ByteSink: ByteIO {
	/// Perform a `puts` operation on the stream.
	/// Parameter should be a null terminated character buffer.
	func put(string: UnsafePointer<Int8>) throws
	/// Writes the buffer to the stream.
	/// Returns the bumber of bytes which were successfully written.
	func write(bytes: UnsafeRawBufferPointer) throws -> Int
}

/// An object which supports `get` and `read` operations.
public protocol ByteSource: ByteIO {
	/// Reads data placing it into the indicated buffer.
	/// A maximum of `bytes.count` bytes will be read.
	/// The number of bytes which were read is returned.
	func read(_ bytes: UnsafeMutableRawBufferPointer) throws -> Int
	/// Perform a `gets` on the stream.
	/// A maximum of `bytes.count` bytes will be read.
	/// The number of bytes which were read is returned.
	/// Data is not null termibated.
	func get(_ bytes: UnsafeMutableRawBufferPointer) throws -> Int
}

/// An object which is used in byte IO filter operations.
public protocol ByteFilter: ByteIO { }

typealias BIOPointer = UnsafeMutablePointer<BIO>?

/// Base class for byte IO objects.
public class ByteIOBase: CustomStringConvertible {
	var bio: BIOPointer
	var head: BIOPointer
	var prev: ByteIOBase?

	fileprivate init(bio: BIOPointer) {
		self.bio = bio
		self.head = bio
		self.prev = nil
	}
	fileprivate init(method: UnsafeMutablePointer<BIO_METHOD>?) {
		let bio = BIO_new(method)
		self.bio = bio
		self.head = bio
		self.prev = nil
	}
	deinit {
		if let bio = bio {
			BIO_free(bio)
			self.bio = nil
			self.head = nil
			self.prev = nil
		}
	}
	public var description: String {
		var ret = ""
		var ptr = head
		while let p = ptr {
			if !ret.isEmpty {
				ret.append("<->")
			}
			if p == bio {
				ret.append("(\(String(validatingUTF8: BIO_method_name(p)) ?? "?"))")
			} else {
				ret.append("\(String(validatingUTF8: BIO_method_name(p)) ?? "?")")
			}
			ptr = BIO_next(p)
		}
		return ret
	}
	fileprivate var streamName: String? {
		return String(validatingUTF8: BIO_method_name(bio))
	}
	private func clear() {
		self.bio = nil
		self.prev?.clear()
		self.prev = nil
	}
	/// Deallocate and clears all underlying objects.
	/// This will destroy the entire IO chain.
	public func close() {
		BIO_free_all(head)
		clear()
	}
	/// Resets the objetc to its initial state.
	/// Exact results depend on the underlying IO object type.
	@discardableResult
	public func reset() -> Self {
		BIO_ctrl(bio, BIO_CTRL_RESET, 0, nil)
		return self
	}
	/// Write out all pending data and/or signal EOF for the stream.
	@discardableResult
	public func flush() throws -> Self {
		try checkedResult(BIO_ctrl(head, BIO_CTRL_FLUSH, 0, nil))
		return self
	}
	/// Returns true if the stream as at end-of-file.
	public var eof: Bool {
		return 1 == BIO_ctrl(head, BIO_CTRL_EOF, 0, nil)
	}
	/// Returns the nuymber of bytes pending for read.
	public var readPending: Int {
		return BIO_ctrl_pending(head)
	}
	/// Returns the number of bytes pending for write.
	public var writePending: Int {
		return BIO_ctrl_wpending(head)
	}
	/// Sets the IO to non-blocking.
	public func setNonBlocking() {
		BIO_ctrl(bio, BIO_C_SET_NBIO, 1, nil)
	}
	/// Chain another object to this IO stream.
	/// IO filter generally go at the front of the chain and sinks/sources go at the end.
	@discardableResult
	public func chain<T: ByteIOBase>(_ next: T) -> T {
		next.prev = self
		next.head = self.head
		BIO_push(self.bio, next.bio)
		return next
	}

	/// Pair this IO chain with the other. 
	/// Any data written to one end can be read on the other and vice versa.
	public func pair(with: ByteIOBase, thisWriteBuffer: Int = 0, thatWriteBuffer: Int = 0) throws {
		try checkedResult(BIO_ctrl(bio, BIO_C_SET_WRITE_BUF_SIZE, thisWriteBuffer, nil))
		try checkedResult(BIO_ctrl(with.bio, BIO_C_SET_WRITE_BUF_SIZE, thatWriteBuffer, nil))
		try checkedResult(BIO_ctrl(bio, BIO_C_MAKE_BIO_PAIR, 0, with.bio))
	}
	/// Detach this object from the chain. Objects before and after this object are bound together.
	@discardableResult
	public func detach() -> Self {
		BIO_pop(bio)
		head = bio
		prev = nil
		return self
	}
	@discardableResult
	func checkedResult(_ result: Int) throws -> Int {
		guard result > -1 else {
			try CryptoError.throwOpenSSLError()
		}
		return result
	}
	@discardableResult
	func checkedResult(_ result: Int32) throws -> Int {
		return try checkedResult(Int(result))
	}
}

extension ByteSink where Self: ByteIOBase {
	public func put(string: UnsafePointer<Int8>) throws {
		try checkedResult(Int(BIO_puts(head, string)))
	}
	public func write(bytes: UnsafeRawBufferPointer) throws -> Int {
		return try checkedResult(Int(BIO_write(head, bytes.baseAddress, Int32(bytes.count))))
	}
}

extension ByteSource where Self: ByteIOBase {
	public func read(_ bytes: UnsafeMutableRawBufferPointer) throws -> Int {
		let result = try checkedResult(BIO_read(head, bytes.baseAddress, Int32(bytes.count)))
		return result
	}
	public func get(_ bytes: UnsafeMutableRawBufferPointer) throws -> Int {
		let result = try checkedResult(BIO_gets(head, bytes.baseAddress?.assumingMemoryBound(to: Int8.self), Int32(bytes.count)))
		return result
	}
}

/// A non-descript byte IO object.
/// Generally returned as a result of using IOPair.
public class GenericIO: ByteIOBase, ByteSink, ByteSource {
	public init() {
		super.init(method: UnsafeMutablePointer(mutating: UnsafePointer(BIO_s_bio())))
	}
	override init(bio: BIOPointer) {
		super.init(bio: bio)
	}
}

/// Creates two byte IO objects which are connected to each other such that 
/// data written on one end can be read from the other and vice versa.
public struct IOPair {
	/// The "first" end of the pair.
	public let first: GenericIO
	/// The "second" end of the pair.
	public let second: GenericIO
	/// Create a new IO pair. The buffers for each end can be indicated.
	/// Data will be pushed only after the buffer size is reached or the chain is flushed.
	/// Default buffer size is approx 4k.
	public init(firstWriteBuffer: Int = 0, secondWriteBuffer: Int = 0) {
		var fPtr: BIOPointer = nil
		var sPtr: BIOPointer = nil
		BIO_new_bio_pair(&fPtr, firstWriteBuffer, &sPtr, secondWriteBuffer)
		self.first = GenericIO(bio: fPtr)
		self.second = GenericIO(bio: sPtr)
	}
}

/// A sink/source object which reads from or writes to a memory buffer.
/// Buffer is automatically resized when writing to it.
public class MemoryIO: ByteIOBase, ByteSink, ByteSource {
	/// The current buffer data held by this object.
	var memory: UnsafeRawBufferPointer? {
		var m: UnsafePointer<Int8>? = nil
		let count = BIO_ctrl(bio, BIO_CTRL_INFO, 0, &m)
		guard let mm = m else {
			return nil
		}
		return UnsafeRawBufferPointer(start: mm, count: count)
	}
	/// Create a new object with no initial data.
	public init() {
		super.init(method: UnsafeMutablePointer(mutating: UnsafePointer(BIO_s_mem())))
	}
	/// Create a new buffer and allocate the indicated number of bytes.
	public convenience init(allocate count: Int) {
		self.init()
		let mem = BUF_MEM_new()
		BUF_MEM_grow(mem, count)
		BIO_ctrl(bio, BIO_C_SET_BUF_MEM, Int(BIO_CLOSE), UnsafeMutableRawPointer(mutating: mem))
	}
	/// Create a new object from an existing data buffer.
	/// Pointer must remain valid while using it as a buffer.
	public init(_ pointer: UnsafeRawBufferPointer) {
		super.init(bio: BIO_new_mem_buf(pointer.baseAddress, Int32(pointer.count)))
	}
	/// Create a new buffer from the indicated data.
	/// The buffer's data is copied to a new buffer and so does not need to remain valid.
	public convenience init(copying: UnsafeRawBufferPointer) {
		self.init()
		let mem = BUF_MEM_new()
		BUF_MEM_grow(mem, copying.count)
		if let data = mem?.pointee.data, let baseAddress = copying.baseAddress {
			memcpy(data, baseAddress, copying.count)
		}
		BIO_ctrl(bio, BIO_C_SET_BUF_MEM, Int(BIO_CLOSE), UnsafeMutableRawPointer(mutating: mem))
	}
	/// Create a new buffer given the string data.
	/// String data is converted to UTF8 and the data is copied to a new buffer.
	public convenience init(_ string: String) {
		var chars = [UInt8](string.utf8)
		let count = chars.count
		self.init()
		let mem = BUF_MEM_new()
		BUF_MEM_grow(mem, count)
		if let data = mem?.pointee.data {
			memcpy(data, &chars, count)
		}
		BIO_ctrl(bio, BIO_C_SET_BUF_MEM, Int(BIO_CLOSE), UnsafeMutableRawPointer(mutating: mem))
	}
}

/// Byte IO object which reads from or write to a file.
public class FileIO: ByteIOBase, ByteSink, ByteSource {
	/// Create a ne wobject with the given file name.
	/// Mode can be any of the standard "FILE" open modes:
	///	  r or rb - Open file for reading.
	///	  w or wb - Truncate to zero length or create file for writing.
	///	  a or ab - Append; open or create file for writing at end-of-file.
	///	  r+ or rb+ or r+b - Open file for update (reading and writing).
	///	  w+ or wb+ or w+b - Truncate to zero length or create file for update.
	///	  a+ or ab+ or a+b - Append; open or create file for update, writing at end-of-file.
	public init(name: String, mode: String) {
		super.init(bio: BIO_new_file(name, mode))
	}
	/// Create a new object with an existing file descriptor.
	/// If `close` is true then the file will be closed when the IO object is destroyed.
	public init(file: Int, close: Bool) {
		super.init(bio: BIO_new_fd(Int32(file), close ? BIO_CLOSE : BIO_NOCLOSE))
	}
	/// Create a new object with an existing socket file descriptor.
	/// If `close` is true then the file will be closed when the IO object is destroyed.
	public init(socket: Int, close: Bool) {
		super.init(bio: BIO_new_socket(Int32(socket), close ? BIO_CLOSE : BIO_NOCLOSE))
	}
}

/// Create a new object capable of reading from STDIN.
public class FileIOStdin: ByteIOBase, ByteSource {
	public init() {
		super.init(bio: BIO_new_fp(stdin, BIO_NOCLOSE))
	}
}

/// Create a new object capable of writing to STDOUT.
public class FileIOStdout: ByteIOBase, ByteSink {
	public init() {
		super.init(bio: BIO_new_fp(stdout, BIO_NOCLOSE))
	}
}

/// Create a new object capable of writing to STDERR.
public class FileIOStderr: ByteIOBase, ByteSink {
	public init() {
		super.init(bio: BIO_new_fp(stderr, BIO_NOCLOSE))
	}
}

/// A sink/source which neither reads nor writes and data.
/// Useful for combining with a filter such as DigestFilter which does not actually 
/// need to store data written through it.
public class NullIO: ByteIOBase, ByteSink, ByteSource {
	public init() {
		super.init(method: UnsafeMutablePointer(mutating: UnsafePointer(BIO_s_null())))
	}
}

/// A sink/source which will accept network connections.
public class AcceptIO: ByteIOBase, ByteSource, ByteSink {
	/// Name is "host:port"
	public init(name: String) {
		super.init(bio: BIO_new_accept(name))
		BIO_ctrl(bio, BIO_C_SET_BIND_MODE, Int(BIO_BIND_REUSEADDR), nil)
	}
	/// Attempt to listen on the indicated address.
	public func listen() throws {
		let result = BIO_ctrl(bio, BIO_C_DO_STATE_MACHINE, 0, nil)
		guard result == 1 else {
			try checkedResult(result)
			return
		}
	}
	/// Wait for a new connectioon to be made.
	public func accept() throws {
		let result = BIO_ctrl(bio, BIO_C_DO_STATE_MACHINE, 0, nil)
		guard result == 1 else {
			try checkedResult(result)
			return
		}
	}
	/// Switch the accept to non-blocking mode.
	public func setNonBlockingAccept() {
		var p: UnsafePointer<Int8>? = nil
		// does not matter what p is, just needs to be non-nil
		BIO_ctrl(bio, BIO_C_SET_ACCEPT, 1, &p)
	}
}

/// A sink/source which will perform a network connection.
public class ConnectIO: ByteIOBase, ByteSource, ByteSink {
	/// Name is "host:port"
	public init(name: String) {
		super.init(bio: BIO_new_connect(name))
	}
	/// Attempt to open the connection.
	public func connect() throws {
		let result = BIO_ctrl(bio, BIO_C_DO_STATE_MACHINE, 0, nil)
		guard result == 1 else {
			try checkedResult(result)
			return
		}
	}
}

/// An IO filter which base 64 *encodes* data *written* to it and
/// base 64 *decodes* any data *read* from it.
public class Base64Filter: ByteIOBase {
	/// Create a new base 64 filter object.
	/// If `requireNewLines` is true then standard base 64 line wrapping will be expected in 
	/// data read and performed on outgoing data.
	public init(requireNewLines: Bool = false) {
		super.init(bio: BIO_new(BIO_f_base64()))
		if !requireNewLines {
			BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL)
		}
	}
}

/// An IO ibject which performs buffering on any reads or writes.
public class BufferFilter: ByteIOBase {
	public static let minimumBufferSize = 4096
	/// Initialize with buffer size. Minimum buffer size is 4k.
	public init(bufferSize: Int = 0) {
		super.init(bio: BIO_new(BIO_f_buffer()))
		if bufferSize > BufferFilter.minimumBufferSize {
			BIO_ctrl(bio, BIO_C_SET_BUFF_SIZE, bufferSize, nil)
		}
	}
}

/// An IO filter which runs the indicated digest algorithm on and data 
/// read from or written to the stream.
/// The resulting digest can be finalized and retreived by calling `gets` on the digest filter itself.
/// The resulting required digest size can be determined through `Digest.length`.
public class DigestFilter: ByteIOBase, ByteSource {
	public init(_ digest: Digest) {
		super.init(method: UnsafeMutablePointer(mutating: UnsafePointer(BIO_f_md())))
		let p = digest.evp
		BIO_ctrl(bio, BIO_C_SET_MD, 1, UnsafeMutableRawPointer(mutating: p))
	}
}

/// An IO object which encrypts all data written through the stream and
/// decrypts data read from it.
public class CipherFilter: ByteIOBase {
	/// Initialize with the indicated cipher, key, iv.
	/// The final parameter, `encrypting`, must be set to control the operation.
	public init(_ cipher: Cipher, key: UnsafePointer<UInt8>, iv: UnsafePointer<UInt8>, encrypting: Bool) {
		super.init(bio: BIO_new(BIO_f_cipher()))
		BIO_set_cipher(bio, cipher.evp, key, iv, encrypting ? 1 : 0)
	}

	/// Checks the status of the *decryption* and throws an error if it failed.
	public func ensureDecryptSuccess() throws {
		try checkedResult(BIO_ctrl(bio, BIO_C_GET_CIPHER_STATUS, 0, nil))
	}
}
