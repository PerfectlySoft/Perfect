//
//  CURLResponse.swift
//  PerfectCURL
//
//  Created by Kyle Jessup on 2017-05-10.
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

import cURL
import Foundation

enum ResponseReadState {
	case status, headers, body
}

/// Response for a CURLRequest. 
/// Obtained by calling CURLResponse.perform.
open class CURLResponse {
	/// A response header that can be retreived.
	public typealias Header = HTTPResponseHeader
	/// A confirmation func thats used to obtain an asynchrnous response.
	public typealias Confirmation = () throws -> CURLResponse
	/// An error thrown while retrieving a response.
	public struct Error: Swift.Error {
		/// The curl specific request response code.
		public let code: Int
		/// The string message for the curl response code.
		public let description: String
		/// The response object for this error.
		public let response: CURLResponse

		init(_ response: CURLResponse, code: CURLcode) {
			self.code = Int(code.rawValue)
			self.description = response.curl.strError(code: code)
			self.response = response
		}
	}

	/// Enum wrapping the typed response info keys.
	// swiftlint:disable todo
	public enum Info {
		/// Info keys with String values.
		public enum StringValue {
			case
				/// The effective URL for the request/response.
				/// This is ultimately the URL from which the response data came from.
				/// This may differ from the request's URL in the case of a redirect.
				url,
				/// The initial path that the request ended up at after logging in to the FTP server.
				ftpEntryPath,
				/// The URL that the request *would have* been redirected to.
				redirectURL,
				/// The local IP address that the request used most recently.
				localIP,
				/// The remote IP address that the request most recently connected to.
				primaryIP,
				/// The content type for the request. This is read from the "Content-Type" header.
				contentType // TODO: this is provided directly by curl (for obvious reason) but might 
							// be confusing given that we parse headers and make them all available through `get`
		}
		/// Info keys with Int values.
		public enum IntValue {
			case
				/// The last received HTTP, FTP or SMTP response code.
				responseCode,
				/// The total size in bytes of all received headers.
				headerSize,
				/// The total size of the issued request in bytes.
				/// This will indicate the cumulative total of all requests sent in the case of a redirect.
				requestSize,
				/// The result of the SSL certificate verification.
				sslVerifyResult,
				// TODO: fileTime only works if the fileTime request option is set
				fileTime,
				/// The total number of redirections that were followed.
				redirectCount,
				/// The last received HTTP proxy response code to a CONNECT request.
				httpConnectCode,
				// TODO: this needs OptionSet enum
				httpAuthAvail,
				// TODO: this needs OptionSet enum
				proxyAuthAvail,
				/// The OS level errno which may have triggered a failure.
				osErrno,
				/// The number of connections that the request had to make in order to produce a response.
				numConnects,
				// TODO: requires the matching time condition options
				conditionUnmet,
				/// The remote port that the request most recently connected to
				primaryPort,
				/// The local port that the request used most recently
				localPort
//				httpVersion // not supported on ubuntu 16 curl??
		}
		// swiftlint:disable todo
		/// Info keys with Double values.
		public enum DoubleValue {
			case
				/// The total time in seconds for the previous request.
				totalTime,
				/// The total time in seconds from the start until the name resolving was completed.
				nameLookupTime,
				/// The total time in seconds from the start until the connection to the remote host or proxy was completed.
				connectTime,
				/// The time, in seconds, it took from the start until the file transfer is just about to begin.
				preTransferTime,
				/// The total number of bytes uploaded.
				sizeUpload, // TODO: why is this a double? curl has it as a double
				/// The total number of bytes downloaded.
				sizeDownload, // TODO: why is this a double? curl has it as a double
				/// The average download speed measured in bytes/second.
				speedDownload,
				/// The average upload speed measured in bytes/second.
				speedUpload,
				/// The content-length of the download. This value is obtained from the Content-Length header field.
				contentLengthDownload,
				/// The specified size of the upload.
				contentLengthUpload,
				/// The time, in seconds, it took from the start of the request until the first byte was received.
				startTransferTime,
				/// The total time, in seconds, it took for all redirection steps include name lookup, connect, pretransfer and transfer before final transaction was started.
				redirectTime,
				/// The time, in seconds, it took from the start until the SSL/SSH connect/handshake to the remote host was completed.
				appConnectTime
		}
//		cookieList, // SLIST
//		certInfo // SLIST
	}

	let curl: CURL
	public internal(set) var headers = Array<(Header.Name, String)>()

	/// The response's raw content body bytes.
	public internal(set) var bodyBytes = [UInt8]()

	var readState = ResponseReadState.status
	// these need to persist until the request has completed execution.
	// this is set by the CURLRequest
	var postFields: CURLRequest.POSTFields?

	init(_ curl: CURL, postFields: CURLRequest.POSTFields?) {
		self.curl = curl
		self.postFields = postFields
	}
}

public extension CURLResponse {
	/// Get an response info String value.
	func get(_ stringValue: Info.StringValue) -> String? {
		return stringValue.get(self)
	}
	/// Get an response info Int value.
	func get(_ intValue: Info.IntValue) -> Int? {
		return intValue.get(self)
	}
	/// Get an response info Double value.
	func get(_ doubleValue: Info.DoubleValue) -> Double? {
		return doubleValue.get(self)
	}
	/// Get a response header value. Returns the first found instance or nil.
	func get(_ header: Header.Name) -> String? {
		return headers.first { header.standardName == $0.0.standardName }?.1
	}
	/// Get a response header's values. Returns all found instances.
	func get(all header: Header.Name) -> [String] {
		return headers.filter { header.standardName == $0.0.standardName }.map { $0.1 }
	}
}

extension CURLResponse {
	func complete() throws {
		setCURLOpts()
		curl.addSLists()
		let resultCode = curl_easy_perform(curl.curl)
		postFields = nil
		guard CURLE_OK == resultCode else {
			throw Error(self, code: resultCode)
		}
	}

	func complete(_ callback: @escaping (Confirmation) -> ()) {
		setCURLOpts()
		innerComplete(callback)
	}

	private func innerComplete(_ callback: @escaping (Confirmation) -> ()) {
		let (notDone, resultCode, _, _) = curl.perform()
		guard Int(CURLE_OK.rawValue) == resultCode else {
			postFields = nil
			return callback({ throw Error(self, code: CURLcode(rawValue: UInt32(resultCode))) })
		}
		if notDone {
			curl.ioWait {
				self.innerComplete(callback)
			}
		} else {
			postFields = nil
			callback({ return self })
		}
	}

	private func addHeaderLine(_ ptr: UnsafeBufferPointer<UInt8>) {
		if readState == .status {
			readState = .headers
		} else if ptr.count == 0 {
			readState = .body
		} else {
			let colon = 58 as UInt8, space = 32 as UInt8
			var pos = 0
			let max = ptr.count

			var tstNamePtr: UnsafeBufferPointer<UInt8>?

			while pos < max {
				defer {	pos += 1 }
				if ptr[pos] == colon {
					tstNamePtr = UnsafeBufferPointer(start: ptr.baseAddress, count: pos)
					while pos < max && ptr[pos+1] == space {
						pos += 1
					}
					break
				}
			}
			guard let namePtr = tstNamePtr, let base = ptr.baseAddress else {
				return
			}
			let valueStart = base+pos
			if valueStart[max-pos-1] == 10 {
				pos += 1
			}
			if valueStart[max-pos-1] == 13 {
				pos += 1
			}
			let valuePtr = UnsafeBufferPointer(start: valueStart, count: max-pos)
			let name = String(bytes: namePtr, encoding: .utf8) ?? ""
			let value = String(bytes: valuePtr, encoding: .utf8) ?? ""
			headers.append((Header.Name.fromStandard(name: name), value))
		}
	}

	private func addBodyData(_ ptr: UnsafeBufferPointer<UInt8>) {
		bodyBytes.append(contentsOf: ptr)
	}

	private func setCURLOpts() {
		let opaqueMe = UnsafeMutableRawPointer(Unmanaged.passUnretained(self).toOpaque())
		curl.setOption(CURLOPT_HEADERDATA, v: opaqueMe)
		curl.setOption(CURLOPT_WRITEDATA, v: opaqueMe)

		do {
			let readFunc: curl_func = { a, size, num, p -> Int in
				let crl = Unmanaged<CURLResponse>.fromOpaque(p!).takeUnretainedValue()
				if let bytes = a?.assumingMemoryBound(to: UInt8.self) {
					let fullCount = size*num
					let minimumHeaderLengthEvenAMalformedOne = 3
					crl.addHeaderLine(UnsafeBufferPointer(start: bytes,
					                                      count: fullCount >= minimumHeaderLengthEvenAMalformedOne ? fullCount : 0))
					return fullCount
				}
				return 0
			}
			curl.setOption(CURLOPT_HEADERFUNCTION, f: readFunc)
		}

		do {
			let readFunc: curl_func = { a, size, num, p -> Int in
				let crl = Unmanaged<CURLResponse>.fromOpaque(p!).takeUnretainedValue()
				if let bytes = a?.assumingMemoryBound(to: UInt8.self) {
					let fullCount = size*num
					crl.addBodyData(UnsafeBufferPointer(start: bytes, count: fullCount))
					return fullCount
				}
				return 0
			}
			curl.setOption(CURLOPT_WRITEFUNCTION, f: readFunc)
		}
	}
}

public extension CURLResponse {
	/// Get the URL which the request may have been redirected to.
	var url: String { return get(.url) ?? "" }
	/// Get the HTTP response code
	var responseCode: Int { return get(.responseCode) ?? 0 }
	/// Get the response body converted from UTF-8.
	var bodyString: String { return String(bytes: bodyBytes, encoding: .utf8) ?? "" }
	/// Get the response body decoded from JSON into a [String:Any] dictionary.
	/// Invalid/non-JSON body data will result in an empty dictionary being returned.
	var bodyJSON: [String: Any] { do { return try bodyString.jsonDecode() as? [String: Any] ?? [:] } catch { return [:] } }
	/// Get the response body decoded from JSON into a decodable structure
	/// Invalid/non-JSON body data will throw errors.
	func bodyJSON<T: Decodable>(_ type: T.Type) throws -> T { return try JSONDecoder().decode(type, from: Data(bodyBytes)) }
}
