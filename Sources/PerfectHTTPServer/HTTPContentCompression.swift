//
//  HTTPContentCompression.swift
//  PerfectHTTPServer
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

import PerfectHTTP
import PerfectCZlib

class ZlibStream {
	var stream = z_stream()
	var closed = false

	init?() {
		stream.zalloc = nil
		stream.zfree = nil
		stream.opaque = nil

		let err = deflateInit_(&stream, Z_DEFAULT_COMPRESSION, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size))
		guard Z_OK == err else {
			return nil
		}
	}

	deinit {
		if !closed {
			close()
		}
	}

	func compress(_ bytes: [UInt8], flush: Bool) -> [UInt8] {
		if bytes.isEmpty && !flush {
			return []
		}
		let needed = Int(compressBound(UInt(bytes.count)))
		let dest = UnsafeMutablePointer<UInt8>.allocate(capacity: needed)
		defer {
			dest.deallocate()
		}
		if !bytes.isEmpty {
            // stream.next_in = UnsafeMutablePointer(mutating: bytes) // dangling pointer fixed.
            stream.next_in = bytes.withUnsafeBufferPointer { bufferedPointer -> UnsafeMutablePointer in
                return UnsafeMutablePointer(mutating: bufferedPointer.baseAddress!)
            }
			stream.avail_in = uInt(bytes.count)
		} else {
			stream.next_in = nil
			stream.avail_in = 0
		}
		var out = [UInt8]()
		repeat {
			stream.next_out = dest
			stream.avail_out = uInt(needed)
			let err = deflate(&stream, flush ? Z_FINISH : Z_NO_FLUSH)
			guard err != Z_STREAM_ERROR else {
				break
			}
			let have = uInt(needed) - stream.avail_out
			let b2 = UnsafeRawBufferPointer(start: dest, count: Int(have))
			out.append(contentsOf: b2.map { $0 })
		} while stream.avail_out == 0
		return out
	}

	func close() {
		if !closed {
			closed = true
			deflateEnd(&stream)
		}
	}
}

private let responseMinSizeNoCompression = 24

public extension HTTPFilter {
	/// Response filter which provides content compression.
	/// Mime types which will be encoded or ignored can be specified with the "compressTypes" and
	/// "ignoreTypes" keys, respectively. The values for these keys should be an array of String
	/// containing either the full mime type or the the main type with a * wildcard. e.g. text/*
	/// The default values for the compressTypes key are: "*/*"
	/// The default values for the ignoreTypes key are: "image/*", "video/*", "audio/*"
	static func contentCompression(data: [String: Any]) throws -> HTTPResponseFilter {
		let inCompressTypes = data["compressTypes"] as? [String] ?? ["*/*"]
		let inIgnoreTypes = data["ignoreTypes"] as? [String] ?? ["image/*", "video/*", "audio/*"]

		struct CompressResponse: HTTPResponseFilter {
			let compressTypes: [MimeType]
			let ignoreTypes: [MimeType]

			func filterHeaders(response: HTTPResponse, callback: (HTTPResponseFilterResult) -> ()) {
				let req = response.request
				if case .head = req.method {
					return callback(.continue)
				}
				if case .notModified = response.status {
					return callback(.continue)
				}
				if !response.isStreaming && response.bodyBytes.count < responseMinSizeNoCompression {
					return callback(.continue)
				}
				if let acceptEncoding = req.header(.acceptEncoding),
					let contentType = contentType(response: response),
					clientWantsCompression(acceptEncoding: acceptEncoding),
					shouldCompress(mimeType: contentType) {

					let skipCheck = response.request.scratchPad["no-compression"] as? Bool ?? false
					if !skipCheck, let stream = ZlibStream() {
						response.setHeader(.contentEncoding, value: "deflate")
						if response.isStreaming {
							response.request.scratchPad["zlib-stream"] = stream
						} else {
							let old = response.bodyBytes
							let new = stream.compress(old, flush: true)
							response.bodyBytes = new
							stream.close()
							response.setHeader(.contentLength, value: "\(new.count)")
						}
					}
				}
				return callback(.continue)
			}

			func filterBody(response: HTTPResponse, callback: (HTTPResponseFilterResult) -> ()) {
				guard response.isStreaming, let stream = response.request.scratchPad["zlib-stream"] as? ZlibStream else {
					return callback(.continue)
				}

				let flush = response.request.scratchPad["_flushing_"] as? Bool ?? false
				response.bodyBytes = stream.compress(response.bodyBytes, flush: flush)
				return callback(.continue)
			}

			private func contentType(response: HTTPResponse) -> String? {
				if let contentType = response.header(.contentType) {
					return contentType
				}
				let path = response.request.path
				return MimeType.forExtension(path.lastFilePathComponent.filePathExtension)
			}

			private func clientWantsCompression(acceptEncoding: String) -> Bool {
				return acceptEncoding.contains("deflate")
			}

			private func shouldCompress(mimeType: String) -> Bool {
				let mime = MimeType(mimeType)
				return compressTypes.contains(mime) && !ignoreTypes.contains(mime)
			}
		}
		return CompressResponse(compressTypes: inCompressTypes.map { MimeType($0) },
		                        ignoreTypes: inIgnoreTypes.map { MimeType($0) })
	}
}
