//
//  StaticFileHandler.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2016-01-06.
//  Copyright © 2016 PerfectlySoft. All rights reserved.
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

import PerfectLib
import PerfectNet
import Foundation

#if os(Linux)
import LinuxBridge
#endif

import COpenSSL

// swiftlint:disable syntactic_sugar
extension String.UTF8View {
	var sha1: [UInt8] {
		let bytes = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(SHA_DIGEST_LENGTH))
		defer { bytes.deallocate() }

		SHA1(Array<UInt8>(self), (self.count), bytes)

		var r = [UInt8]()
		for idx in 0..<Int(SHA_DIGEST_LENGTH) {
			r.append(bytes[idx])
		}
		return r
	}
}

extension UInt8 {
	// same as String(self, radix: 16)
	// but outputs two characters. i.e. 0 padded
	var hexString: String {
		let s = String(self, radix: 16)
		if s.count == 1 {
			return "0" + s
		}
		return s
	}
}

/// A web request handler which can be used to return static disk-based files to the client.
/// Supports byte ranges, ETags and streaming very large files.
public struct StaticFileHandler {
	static public let defaultChunkedBufferSize = 1024*200

	let chunkedBufferSize: Int
	let documentRoot: String
	let allowResponseFilters: Bool

	/// Public initializer given a document root.
	/// If allowResponseFilters is false (which is the default) then the file will be sent in
	/// the most effecient way possible and output filters will be bypassed.
	public init(documentRoot: String, allowResponseFilters: Bool = false, chunkedBufferSize: Int = defaultChunkedBufferSize) {
		self.documentRoot = documentRoot
		self.allowResponseFilters = allowResponseFilters
		self.chunkedBufferSize = chunkedBufferSize
	}

	/// Main entry point. A registered URL handler should call this and pass the request and response objects.
	/// After calling this, the StaticFileHandler owns the request and will handle it until completion.
	public func handleRequest(request: HTTPRequest, response: HTTPResponse) {
		func fnf(msg: String) {
			response.status = .notFound
			response.appendBody(string: msg)
			// !FIX! need 404.html or some such thing
			response.completed()
		}
		var pathComponents = request.pathComponents
		if pathComponents.last == "/" {
			pathComponents.removeLast()
			pathComponents.append("index.html") // !FIX! needs to be configurable
		}
		if pathComponents.first == "/" {
			pathComponents.removeFirst()
		}
		let path = pathComponents.joined(separator: "/")
		guard let sanitized = sanitizePathTraversal(path) else {
			return fnf(msg: "The file /\(path) could not be opened.")
		}
		let file = File(documentRoot + "/" + sanitized)
		guard file.exists else {
			return fnf(msg: "The file /\(path) was not found.")
		}
		do {
			try file.open(.read)
			self.sendFile(request: request, response: response, file: file)
		} catch {
			return fnf(msg: "The file /\(path) could not be opened \(error).")
		}
	}
	// returns nil if the path is invalid
	func sanitizePathTraversal(_ path: String) -> String? {
		var ret: [String] = []
		for component in path.filePathComponents {
			switch component {
			case "", "/", ".": continue
			case "..":
				if ret.isEmpty { // invalid
					return nil
				}
				ret.removeLast()
			default:
				ret.append(component)
			}
		}
		return ret.joined(separator: "/")
	}

	func shouldSkipSendfile(response: HTTPResponse) -> Bool {
		if self.allowResponseFilters {
			return true
		}
		// can not use sendfile for SSL requests
		if let sslCon = response.request.connection as? NetTCPSSL {
			return sslCon.usingSSL
		}
		return false
	}

	func sendFile(request: HTTPRequest, response: HTTPResponse, file: File) {

		response.addHeader(.acceptRanges, value: "bytes")

		if let rangeRequest = request.header(.range) {
			return self.performRangeRequest(rangeRequest: rangeRequest, request: request, response: response, file: file)
		} else if let ifNoneMatch = request.header(.ifNoneMatch) {
			let eTag = self.getETag(file: file)
			if ifNoneMatch == eTag {
				response.status = .notModified
				return response.next()
			}
		}

		let size = file.size
		let contentType = MimeType.forExtension(file.path.filePathExtension)

		response.status = .ok
		response.addHeader(.contentType, value: contentType)

		if allowResponseFilters {
			response.isStreaming = true
		} else {
			response.addHeader(.contentLength, value: "\(size)")
		}

		self.addETag(response: response, file: file)

		if case .head = request.method {
			return response.next()
		}

		// send out headers
		response.push { ok in
			guard ok else {
				file.close()
				return response.completed()
			}
			self.sendFile(remainingBytes: size, response: response, file: file) { _ in
				file.close()
				response.next()
			}
		}
	}

	func performRangeRequest(rangeRequest: String, request: HTTPRequest, response: HTTPResponse, file: File) {
		let size = file.size
		let ranges = self.parseRangeHeader(fromHeader: rangeRequest, max: size)
		if ranges.count == 1 {
			let range = ranges[0]
			let rangeCount = range.count
			let contentType = MimeType.forExtension(file.path.filePathExtension)

			response.status = .partialContent
			response.addHeader(.contentLength, value: "\(rangeCount)")
			response.addHeader(.contentType, value: contentType)
			response.addHeader(.contentRange, value: "bytes \(range.lowerBound)-\(range.upperBound-1)/\(size)")

			if case .head = request.method {
				return response.next()
			}

			file.marker = range.lowerBound
			// send out headers
			response.push { ok in
				guard ok else {
					file.close()
					return response.completed()
				}
				return self.sendFile(remainingBytes: rangeCount, response: response, file: file) { _ in
					file.close()
					response.next()
				}
			}
		} else if ranges.count > 0 {
			// !FIX! support multiple ranges
			response.status = .internalServerError
			return response.completed()
		} else {
			response.status = .badRequest
			return response.completed()
		}
	}

	func getETag(file: File) -> String {
		let eTagStr = file.path + "\(file.modificationTime)"
		let eTag = eTagStr.utf8.sha1
		let eTagReStr = eTag.map { $0.hexString }.joined(separator: "")

		return eTagReStr
	}

	func addETag(response: HTTPResponse, file: File) {
		let eTag = self.getETag(file: file)
		response.addHeader(.eTag, value: eTag)
	}

	func sendFile(remainingBytes remaining: Int, response: HTTPResponse, file: File, completion: @escaping (Bool) -> ()) {
		if self.shouldSkipSendfile(response: response) {
			let thisRead = min(chunkedBufferSize, remaining)
			do {
				let bytes = try file.readSomeBytes(count: thisRead)
				response.appendBody(bytes: bytes)
				response.push { ok in
					if !ok || thisRead == remaining {
						// done
						completion(ok)
					} else {
						self.sendFile(remainingBytes: remaining - bytes.count, response: response, file: file, completion: completion)
					}
				}
			} catch {
				completion(false)
			}
		} else {
			let outFd = response.request.connection.fd.fd
			let inFd = file.fd
			#if os(Linux)
			let toSend = off_t(remaining)
			let result = sendfile(outFd, Int32(inFd), nil, toSend)
			if result >= 0 {
				let newRemaining = remaining - result
				if newRemaining == 0 {
					return completion(true)
				}
				self.sendFile(remainingBytes: newRemaining, response: response, file: file, completion: completion)
			} else if result == -1 && errno == EAGAIN {
				NetEvent.add(socket: outFd, what: .write, timeoutSeconds: 5.0) { _, what in
					if case .write = what {
						self.sendFile(remainingBytes: remaining, response: response, file: file, completion: completion)
					} else {
						completion(false)
					}
				}
			} else {
				completion(false)
			}
			#else
			let offset = off_t(file.marker)
			var toSend = off_t(remaining)
			let result = sendfile(Int32(inFd), outFd, offset, &toSend, nil, 0)
			if result == 0 {
				completion(true)
			} else	if result == -1 && errno == EAGAIN {
				file.marker = Int(offset) + Int(toSend)
				let newRemaining = remaining - Int(toSend)
				NetEvent.add(socket: outFd, what: .write, timeoutSeconds: 5.0) { _, what in
					if case .write = what {
						self.sendFile(remainingBytes: newRemaining, response: response, file: file, completion: completion)
					} else {
						completion(false)
					}
				}
			} else {
				completion(false)
			}
			#endif
		}
	}

	// bytes=0-3/7-9/10-15
	func parseRangeHeader(fromHeader header: String, max: Int) -> [Range<Int>] {
		let initialSplit = header.split(separator: "=")
		guard initialSplit.count == 2 && String(initialSplit[0]) == "bytes" else {
			return [Range<Int>]()
		}
		let ranges = initialSplit[1]
		return ranges.split(separator: "/").compactMap { self.parseOneRange(fromString: String($0), max: max) }
	}

	// 0-3
	// 0-
	func parseOneRange(fromString string: String, max: Int) -> Range<Int>? {
		let split = string.split(separator: "-", omittingEmptySubsequences: false).map { String($0) }
		guard split.count == 2 else {
			return nil
		}
		if split[1].isEmpty {
			guard let lower = Int(split[0]),
				lower <= max else {
					return nil
			}
			return Range(uncheckedBounds: (lower, max))
		}
		guard let lower = Int(split[0]),
			let upperRaw = Int(split[1]) else {
				return nil
		}
		let upper = Swift.min(max, upperRaw+1)
		guard lower <= upper else {
			return nil
		}
		return Range(uncheckedBounds: (lower, upper))
	}
}
