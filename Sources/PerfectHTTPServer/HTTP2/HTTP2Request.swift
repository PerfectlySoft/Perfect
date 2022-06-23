//
//  HTTP2.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2016-02-18.
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

import PerfectHTTP
import PerfectNet
import PerfectLib
import PerfectThread

final class HTTP2Request: HTTPRequest, HeaderListener {
	var method: HTTPMethod = .get
	var path: String {
		get {
			var accum = ""
			var lastSlashExplicit = false
			for p in pathComponents {
				if p == "/" {
					accum += p
					lastSlashExplicit = true
				} else {
					if !lastSlashExplicit {
						accum += "/"
					}
					accum += p.stringByEncodingURL
					lastSlashExplicit = false
				}
			}
			return accum
		}
		set {
			let components = newValue.filePathComponents.map { $0 == "/" ? "/" : $0.stringByDecodingURL ?? "" }
			pathComponents = components
		}
	}
	var pathComponents = [String]()
	var queryString = ""
	var scheme = ""
	var authority = ""
	lazy var queryParams: [(String, String)] = {
		return deFormURLEncoded(string: queryString)
	}()
	var protocolVersion = (2, 0)
	var remoteAddress: (host: String, port: UInt16) {
		guard let remote = connection.remoteAddress else {
			return ("", 0)
		}
		return (remote.host, remote.port)
	}
	var serverAddress: (host: String, port: UInt16) {
		guard let local = connection.localAddress else {
			return ("", 0)
		}
		return (local.host, local.port)
	}
	var serverName: String { return session?.server.serverName ?? "" }
	var documentRoot: String { return session?.server.documentRoot ?? "./" }
	var connection: NetTCP
	var urlVariables: [String: String] = [:]
	var scratchPad: [String: Any] = [:]
    // swiftlint:disable syntactic_sugar
	private var headerStore = Dictionary<HTTPRequestHeader.Name, [UInt8]>()
	var headers: AnyIterator<(HTTPRequestHeader.Name, String)> {
		var g = self.headerStore.makeIterator()
		return AnyIterator<(HTTPRequestHeader.Name, String)> {
			guard let n = g.next() else {
				return nil
			}
			return (n.key, UTF8Encoding.encode(bytes: n.value))
		}
	}

	func header(_ named: HTTPRequestHeader.Name) -> String? {
		guard let v = headerStore[named] else {
			return nil
		}
		return UTF8Encoding.encode(bytes: v)
	}

	func addHeader(_ named: HTTPRequestHeader.Name, value: String) {
		guard let existing = headerStore[named] else {
			self.headerStore[named] = [UInt8](value.utf8)
			return
		}
		let valueBytes = [UInt8](value.utf8)
		let newValue: [UInt8]
		if named == .cookie {
			newValue = existing + "; ".utf8 + valueBytes
		} else {
			newValue = existing + ", ".utf8 + valueBytes
		}
		self.headerStore[named] = newValue
	}

	func setHeader(_ named: HTTPRequestHeader.Name, value: String) {
		headerStore[named] = [UInt8](value.utf8)
	}

	lazy var postParams: [(String, String)] = {

		if let mime = self.mimes {
			return mime.bodySpecs.filter { $0.file == nil }.map { ($0.fieldName, $0.fieldValue) }
		} else if let bodyString = self.postBodyString {
			return self.deFormURLEncoded(string: bodyString)
		}
		return [(String, String)]()
	}()
	var postBodyBytes: [UInt8]?  = nil
	var postBodyString: String? {
		guard let bytes = postBodyBytes else {
			return nil
		}
		if bytes.isEmpty {
			return ""
		}
		return UTF8Encoding.encode(bytes: bytes)
	}
	var postFileUploads: [MimeReader.BodySpec]? {
		guard let mimes = self.mimes else {
			return nil
		}
		return mimes.bodySpecs
	}

	weak var session: HTTP2Session?
	var decoder: HPACKDecoder { return session!.decoder }
	let streamId: UInt32
	var streamState = HTTP2StreamState.idle
	var streamFlowWindows: HTTP2FlowWindows
	var encodedHeadersBlock = [UInt8]()
	var endOfHeaders = false
	var unblockCallback: (() -> ())?
	var debug: Bool { return session?.debug ?? false }
	var mimes: MimeReader?

	init(_ streamId: UInt32, session: HTTP2Session) {
		connection = session.net
		self.streamId = streamId
		self.session = session
		streamFlowWindows = HTTP2FlowWindows(serverWindowSize: session.serverSettings.initialWindowSize,
		                                     clientWindowSize: session.clientSettings.initialWindowSize)
	}

	deinit {
		if debug { print("~HTTP2Request \(streamId)") }
	}

	func decodeHeadersBlock() {
		do {
			decoder.reset()
			try decoder.decode(input: Bytes(existingBytes: encodedHeadersBlock), headerListener: self)
		} catch {
			session?.fatalError(streamId: streamId, error: .compressionError, msg: "error while decoding headers \(error)")
			streamState = .closed
		}
		encodedHeadersBlock = []
	}

	func headersFrame(_ frame: HTTP2Frame) {
		let endOfStream = (frame.flags & flagEndStream) != 0
		if endOfStream {
			streamState = .halfClosed
		} else {
			streamState = .open
		}
		endOfHeaders = (frame.flags & flagEndHeaders) != 0
		if debug {
			print("\tstream: \(streamId)")
		}
		let padded = (frame.flags & flagPadded) != 0
		let priority = (frame.flags & flagPriority) != 0
		if let ba = frame.payload, ba.count > 0 {
			let bytes = Bytes(existingBytes: ba)
			var padLength: UInt8 = 0
			if padded {
				padLength = bytes.export8Bits()
				bytes.data.removeLast(Int(padLength))
			}
			if priority {
				_/*streamDep*/ = bytes.export32Bits()
				_/*weight*/ = bytes.export8Bits()
			}
			encodedHeadersBlock += bytes.exportBytes(count: bytes.availableExportBytes)
		}
		if endOfHeaders {
			decodeHeadersBlock()
		}
		if endOfHeaders && endOfStream {
			processRequest()
		} else {
			session?.increaseServerWindow(stream: streamId, by: receiveWindowTopOff)
		}
	}

	func continuationFrame(_ frame: HTTP2Frame) {
		guard !endOfHeaders, streamState == .open else {
			session?.fatalError(streamId: streamId, error: .protocolError, msg: "Invalid frame")
			return
		}
		let endOfStream = (frame.flags & flagEndStream) != 0
		if endOfStream {
			streamState = .halfClosed
		}
		endOfHeaders = (frame.flags & flagEndHeaders) != 0
		if debug {
			print("\tstream: \(streamId)")
		}
		if let ba = frame.payload, ba.count > 0 {
			encodedHeadersBlock += ba
		}
		if endOfHeaders {
			decodeHeadersBlock()
		}
		if endOfHeaders && endOfStream {
			processRequest()
		} else {
			session?.increaseServerWindow(stream: streamId, by: receiveWindowTopOff)
		}
	}

	// session handles window adjustments
	func dataFrame(_ frame: HTTP2Frame) {
		let endOfStream = (frame.flags & flagEndStream) != 0
		let bytes = frame.payload ?? []
		let padded = (frame.flags & flagPadded) != 0
		if debug {
			print("request \(streamId) POST bytes: \(bytes.count), recv window: \(streamFlowWindows.serverWindowSize), EOS: \(endOfStream), padded: \(padded)")
		}
		if padded {
			let padSize = Int(bytes[0])
			let lastIndex = bytes.count - padSize
			putPostData(Array(bytes[1..<lastIndex]))
		} else {
			putPostData(bytes)
		}
		if endOfStream {
			processRequest()
		}
	}

	func priorityFrame(_ frame: HTTP2Frame) {

	}

	func cancelStreamFrame(_ frame: HTTP2Frame) {
		streamState = .closed
		if let u = unblockCallback {
			unblockCallback = nil
			u()
		}
	}

	func putPostData(_ b: [UInt8]) {
		if let mimes = self.mimes {
			return mimes.addToBuffer(bytes: b)
		} else {
			if nil == postBodyBytes {
				postBodyBytes = b
			} else {
				postBodyBytes?.append(contentsOf: b)
			}
		}
	}

	func processRequest() {
		let response = HTTP2Response(self)
		netHandleQueue.async { // get off the frame read thread
			self.routeRequest(response: response)
		}
	}

	func routeRequest(response: HTTPResponse) {
		session?.server.filterAndRun(request: self, response: response)
	}

	// scheme, authority
	func addHeader(name: [UInt8], value: [UInt8], sensitive: Bool) {
		let n = String(validatingUTF8: name) ?? ""
		switch n {
		case ":method":
			method = HTTPMethod.from(string: String(validatingUTF8: value) ?? "")
		case ":path":
			(self.pathComponents, self.queryString) = parseURI(pathBuffer: value)
		case ":scheme":
			scheme = UTF8Encoding.encode(bytes: value)
		case ":authority":
			authority = UTF8Encoding.encode(bytes: value)
		default:
			let headerName = HTTPRequestHeader.Name.fromStandard(name: n)
			if headerName == .contentType {
				let contentType = String(validatingUTF8: value) ?? ""
				if contentType.starts(with: "multipart/form-data") {
					self.mimes = MimeReader(contentType)
				}
			}
			headerStore[headerName] = value
		}
		if debug {
			print("\t\(n): \(UTF8Encoding.encode(bytes: value))")
		}
	}
}

extension HTTP2Request {
	func deFormURLEncoded(string: String) -> [(String, String)] {
		return string.split(separator: "&").map(String.init).compactMap {
			let d = $0.split(separator: "=", maxSplits: 1).compactMap { String($0).stringByDecodingURL }
			if d.count == 2 { return (d[0], d[1]) }
			if d.count == 1 { return (d[0], "") }
			return nil
		}
	}
	// parse from workingBuffer contents
	func parseURI(pathBuffer: [UInt8]) -> ([String], String) {
		enum ParseURLState {
			case slash, component, query
		}
		var state = ParseURLState.slash
		var gen = pathBuffer.makeIterator()
		var decoder = UTF8()
		var pathComponents = ["/"]
		var component = ""
		var queryString = ""

		let question = UnicodeScalar(63)
		let slash = UnicodeScalar(47)

		loopy:
			repeat {
				let res = decoder.decode(&gen)
				switch res {
				case .scalarValue(let uchar):
					switch state {
					case .slash:
						if uchar == question {
							state = .query
							pathComponents.append("/")
						} else if uchar != slash {
							state = .component
							component = String(Character(uchar))
						}
					case .component:
						if uchar == question {
							state = .query
							pathComponents.append(component.stringByDecodingURL ?? "")
						} else if uchar == slash {
							state = .slash
							pathComponents.append(component.stringByDecodingURL ?? "")
						} else {
							component.append(Character(uchar))
						}
					case .query:
						queryString.append(Character(uchar))
					}
				case .emptyInput, .error:
					switch state {
					case .slash:
						if pathComponents.count > 1 {
							pathComponents.append("/")
						}
					case .component:
						pathComponents.append(component.stringByDecodingURL ?? "")
					case .query:
						()
					}
					break loopy
				}
		} while true
		return (pathComponents, queryString)
	}
}

extension HTTP2Request {
	func canSend(count: Int) -> Bool {
		return session!.connectionFlowWindows.clientWindowSize - count > 0 &&
			streamFlowWindows.clientWindowSize - count > 0
	}

	func canRecv(count: Int) -> Bool {
		return session!.connectionFlowWindows.serverWindowSize - count > 0 &&
			streamFlowWindows.serverWindowSize - count > 0
	}
}
