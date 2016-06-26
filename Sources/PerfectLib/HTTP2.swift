//
//  HTTP2.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2016-02-18.
//  Copyright © 2016 PerfectlySoft. All rights reserved.
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

// NOTE: This HTTP/2 client is competent enough to operate with Apple's push notification service, but
// still lacks some functionality to make it general purpose. Consider it a work in-progress.

import PerfectNet
import PerfectThread

#if os(Linux)
import SwiftGlibc
#endif

let HTTP2_DATA: UInt8 = 0x0
let HTTP2_HEADERS: UInt8 = 0x1
let HTTP2_PRIORITY: UInt8 = 0x2
let HTTP2_RST_STREAM: UInt8 = 0x3
let HTTP2_SETTINGS: UInt8 = 0x4
let HTTP2_PUSH_PROMISE: UInt8 = 0x5
let HTTP2_PING: UInt8 = 0x6
let HTTP2_GOAWAY: UInt8 = 0x7
let HTTP2_WINDOW_UPDATE: UInt8 = 0x8
let HTTP2_CONTINUATION: UInt8 = 0x9

let HTTP2_END_STREAM: UInt8 = 0x1
let HTTP2_END_HEADERS: UInt8 = 0x4
let HTTP2_PADDED: UInt8 = 0x8
let HTTP2_FLAG_PRIORITY: UInt8 = 0x20
let HTTP2_SETTINGS_ACK = HTTP2_END_STREAM
let HTTP2_PING_ACK = HTTP2_END_STREAM

let SETTINGS_HEADER_TABLE_SIZE: UInt16 = 0x1
let SETTINGS_ENABLE_PUSH: UInt16 = 0x2
let SETTINGS_MAX_CONCURRENT_STREAMS: UInt16 = 0x3
let SETTINGS_INITIAL_WINDOW_SIZE: UInt16 = 0x4
let SETTINGS_MAX_FRAME_SIZE: UInt16 = 0x5
let SETTINGS_MAX_HEADER_LIST_SIZE: UInt16 = 0x6

struct HTTP2Frame {
	let length: UInt32 // 24-bit
	let type: UInt8
	let flags: UInt8
	let streamId: UInt32 // 31-bit
	var payload: [UInt8]?

	var typeStr: String {
		switch self.type {
		case HTTP2_DATA:
			return "HTTP2_DATA"
		case HTTP2_HEADERS:
			return "HTTP2_HEADERS"
		case HTTP2_PRIORITY:
			return "HTTP2_PRIORITY"
		case HTTP2_RST_STREAM:
			return "HTTP2_RST_STREAM"
		case HTTP2_SETTINGS:
			return "HTTP2_SETTINGS"
		case HTTP2_PUSH_PROMISE:
			return "HTTP2_PUSH_PROMISE"
		case HTTP2_PING:
			return "HTTP2_PING"
		case HTTP2_GOAWAY:
			return "HTTP2_GOAWAY"
		case HTTP2_WINDOW_UPDATE:
			return "HTTP2_WINDOW_UPDATE"
		case HTTP2_CONTINUATION:
			return "HTTP2_CONTINUATION"
		default:
			return "UNKNOWN_TYPE"
		}
	}
	
	var flagsStr: String {
		var s = ""
		if flags == 0 {
			s.append("NO FLAGS")
		}
		if (flags & HTTP2_END_STREAM) != 0 {
			s.append(" +HTTP2_END_STREAM")
		}
		if (flags & HTTP2_END_HEADERS) != 0 {
			s.append(" +HTTP2_END_HEADERS")
		}
		return s
	}
	
	func headerBytes() -> [UInt8] {
		var data = [UInt8]()

		let l = length.hostToNet >> 8
		data.append(UInt8(l & 0xFF))
		data.append(UInt8((l >> 8) & 0xFF))
		data.append(UInt8((l >> 16) & 0xFF))

		data.append(type)
		data.append(flags)

		let s = streamId.hostToNet
		data.append(UInt8(s & 0xFF))
		data.append(UInt8((s >> 8) & 0xFF))
		data.append(UInt8((s >> 16) & 0xFF))
		data.append(UInt8((s >> 24) & 0xFF))
		return data
	}
}

final class HTTP2Request: HTTP11Request {

    
}

final class HTTP2Response: HTTP11Response, HeaderListener {

	func addHeader(name nam: [UInt8], value: [UInt8], sensitive: Bool) {
		let n = UTF8Encoding.encode(bytes: nam)
		let v = UTF8Encoding.encode(bytes: value)

		switch n {
		case ":status":
			self.status = HTTPResponseStatus.statusFrom(code: Int(v) ?? 200)
		default:
			headerStore.append((HTTPResponseHeader.Name.fromStandard(name: n), v))
		}
	}
}

public class HTTP2Client {

	enum StreamState {
		case none, idle, reservedLocal, reservedRemote, open, halfClosedRemote, halfClosedLocal, closed
	}

	public let net = NetTCPSSL()
	var host = ""
	var timeoutSeconds = 5.0
	var ssl = true
	var streams = [UInt32:StreamState]()
	var streamCounter = UInt32(1)
	
	var encoder = HPACKEncoder()
	
	let closeLock = Threading.Lock()
	
	let frameReadEvent = Threading.Event()
	var frameQueue = [HTTP2Frame]()
	var frameReadOK = false

	var newStreamId: UInt32 {
		streams[streamCounter] = StreamState.none
		let s = streamCounter
		streamCounter += 2
		return s
	}

	public init() {

	}

	func dequeueFrame(timeoutSeconds timeout: Double) -> HTTP2Frame? {
		var frame: HTTP2Frame? = nil

		self.frameReadEvent.doWithLock {
			if self.frameQueue.count == 0 {
				let _ = self.frameReadEvent.wait(seconds: timeout)
			}
			if self.frameQueue.count > 0 {
				frame = self.frameQueue.removeFirst()
			}
		}

		return frame
	}

	func dequeueFrame(timeoutSeconds timeout: Double, streamId: UInt32) -> HTTP2Frame? {
		var frame: HTTP2Frame? = nil

		self.frameReadEvent.doWithLock {
			if self.frameQueue.count == 0 {
				let _ = self.frameReadEvent.wait(seconds: timeout)
			}
			if self.frameQueue.count > 0 {
				for i in 0..<self.frameQueue.count {
					let frameTest = self.frameQueue[i]
					if frameTest.streamId == streamId {
						self.frameQueue.remove(at: i)
						frame = frameTest
						break
					}
				}
			}
		}

		return frame
	}

	func processSettingsPayload(_ b: Bytes) {
		while b.availableExportBytes >= 6 {
			let identifier = b.export16Bits().netToHost
//			let value = b.export32Bits().netToHost

//			print("Setting \(identifier) \(value)")
			
			switch identifier {
			case SETTINGS_HEADER_TABLE_SIZE:
				()//self.encoder = HPACKEncoder(maxCapacity: Int(value))
			case SETTINGS_ENABLE_PUSH:
				()
			case SETTINGS_MAX_CONCURRENT_STREAMS:
				()
			case SETTINGS_INITIAL_WINDOW_SIZE:
				()
			case SETTINGS_MAX_FRAME_SIZE:
				()
			case SETTINGS_MAX_HEADER_LIST_SIZE:
				()
			default:
				()
			}
		}
	}

	func readOneFrame() {
		Threading.dispatch {
			self.readHTTP2Frame(timeout: -1) { [weak self]
				f in
				if let frame = f {
//					print("Read frame \(frame.typeStr) \(frame.flagsStr) \(frame.streamId)")
//					if frame.length > 0 {
//						print("Read frame payload \(frame.length) \(UTF8Encoding.encode(frame.payload!))")
//					}
					self?.frameReadEvent.doWithLock {
						switch frame.type {
						case HTTP2_SETTINGS:
							let endStream = (frame.flags & HTTP2_SETTINGS_ACK) != 0
							if !endStream { // ACK settings receipt
								if let payload = frame.payload {
									self?.processSettingsPayload(Bytes(existingBytes: payload))
								}
								let response = HTTP2Frame(length: 0, type: HTTP2_SETTINGS, flags: HTTP2_SETTINGS_ACK, streamId: 0, payload: nil)
								self?.writeHTTP2Frame(response) {
									b in
									self?.readOneFrame()
								}
							} else { // ACK of our settings frame
								self?.readOneFrame()
							}
						case HTTP2_PING:
							let endStream = (frame.flags & HTTP2_PING_ACK) != 0
							if !endStream { // ACK ping receipt
								if let payload = frame.payload {
									self?.processSettingsPayload(Bytes(existingBytes: payload))
								}
								let response = HTTP2Frame(length: frame.length, type: HTTP2_PING, flags: HTTP2_PING_ACK, streamId: 0, payload: frame.payload)
								self?.writeHTTP2Frame(response) {
									b in
									self?.readOneFrame()
								}
							} else { // ACK of our ping frame
								self?.readOneFrame()
							}
						default:
							self?.frameQueue.append(frame)
							self?.frameReadOK = true
							let _ = self?.frameReadEvent.broadcast()
						}
					}
				} else { // network error
					self?.frameReadEvent.doWithLock {
						self?.close()
						self?.frameReadOK = false
						let _ = self?.frameReadEvent.broadcast()
					}
				}
			}
		}
	}

	func startReadThread() {
		Threading.dispatch { [weak self] in
			// dbg
			defer {
				print("~HTTP2Client.startReadThread")
			}
            guard let net = self?.net else {
                return
            }
            while net.isValid {
                guard let s = self else {
                    net.close()
                    break
                }
                s.frameReadEvent.doWithLock {
                    s.frameReadOK = false
                    s.readOneFrame()
                    if !s.frameReadOK && net.isValid {
                        _ = s.frameReadEvent.wait()
                    }
                }
                if !s.frameReadOK {
                    s.close()
                    break
                }
            }
		}
	}

	public func close() {
		self.closeLock.doWithLock {
			self.net.close()
		}
	}

	public var isConnected: Bool {
		return self.net.isValid
	}

	public func connect(host hst: String, port: UInt16, ssl: Bool, timeoutSeconds: Double, callback: (Bool) -> ()) {
		self.host = hst
		self.ssl = ssl
		self.timeoutSeconds = timeoutSeconds

		do {
			try net.connect(address: hst, port: port, timeoutSeconds: timeoutSeconds) {
				n in

				if let net = n as? NetTCPSSL {

					if ssl {
						net.beginSSL {
							b in

							if b {
								self.completeConnect(callback)
							} else {
								callback(false)
							}
						}
					} else {
						self.completeConnect(callback)
					}

				} else {
					callback(false)
				}
			}
		} catch {
			callback(false)
		}
	}

	public func createRequest() -> HTTPRequest {
		return HTTP2Request(connection: self.net)
	}

	func awaitResponse(streamId stream: UInt32, request: HTTPRequest, callback: (HTTPResponse?, String?) -> ()) {
        let response = HTTP2Response(request: request)
		var streamOpen = true
		while streamOpen {
			let f = self.dequeueFrame(timeoutSeconds: self.timeoutSeconds, streamId: stream)

			if let frame = f {

				switch frame.type {
				case HTTP2_GOAWAY:
					let bytes = Bytes(existingBytes: frame.payload!)
					let streamId = bytes.export32Bits().netToHost
					let errorCode = bytes.export32Bits().netToHost
					var message = ""
					if bytes.availableExportBytes > 0 {
						message = UTF8Encoding.encode(bytes: bytes.exportBytes(count: bytes.availableExportBytes))
					}

					let bytes2 = Bytes()
					let _ = bytes2.import32Bits(from: streamId.hostToNet)
                            .import32Bits(from: 0)
					let frame2 = HTTP2Frame(length: 8, type: HTTP2_GOAWAY, flags: 0, streamId: streamId, payload: bytes2.data)
					self.writeHTTP2Frame(frame2) {
						b in

						self.close()
					}
					callback(nil, "\(errorCode) \(message)")
					streamOpen = false
				case HTTP2_HEADERS:
					let padded = (frame.flags & HTTP2_PADDED) != 0
//					let priority = (frame.flags & HTTP2_PRIORITY) != 0
//					let end = (frame.flags & HTTP2_END_HEADERS) != 0

					if let ba = frame.payload where ba.count > 0 {
						let bytes = Bytes(existingBytes: ba)
						var padLength: UInt8 = 0
//										var streamDep = UInt32(0)
//										var weight = UInt8(0)

						if padded {
							padLength = bytes.export8Bits()
						}
//										if priority {
//											streamDep = bytes.export32Bits()
//											weight = bytes.export8Bits()
//										}
						self.decodeHeaders(from: bytes, endPosition: ba.count - Int(padLength), listener: response)
					}
					streamOpen = (frame.flags & HTTP2_END_STREAM) == 0
					if !streamOpen {
						callback(response, nil)
					}
				case HTTP2_DATA:
					if let payload = frame.payload where frame.length > 0 {
                        response.appendBody(bytes: payload)
					}
					streamOpen = (frame.flags & HTTP2_END_STREAM) == 0
					if !streamOpen {
						callback(response, nil)
					}
				default:
					streamOpen = false
					callback(nil, "Unexpected frame type \(frame.typeStr)")
				}

			} else {
				self.close()
				streamOpen = false
				callback(nil, "Connection dropped")
			}
		}
	}

	public func sendRequest(_ request: HTTPRequest, callback: (HTTPResponse?, String?) -> ()) {
		let streamId = self.newStreamId
		self.streams[streamId] = .idle

		let headerBytes = Bytes()

		let method = request.method
		let scheme = ssl ? "https" : "http"
		let path = request.uri

		do {

			try encoder.encodeHeader(out: headerBytes, nameStr: ":method", valueStr: method.description)
			try encoder.encodeHeader(out: headerBytes, nameStr: ":scheme", valueStr: scheme)
			try encoder.encodeHeader(out: headerBytes, nameStr: ":path", valueStr: path ?? "/", sensitive: false, incrementalIndexing: false)
			try encoder.encodeHeader(out: headerBytes, nameStr: "host", valueStr: self.host)
			try encoder.encodeHeader(out: headerBytes, nameStr: "content-length", valueStr: "\(request.postBodyBytes?.count ?? 0)")

			for (name, value) in request.headers {
				let lowered  = name.standardName
				var inc = true
				// this is APNS specific in that Apple wants the apns-id and apns-expiration headers to be indexed on the first request but not indexed on subsequent requests
				// !FIX! need to enable the caller to indicate policies such as this
				let n = UTF8Encoding.decode(string: lowered)
				let v = UTF8Encoding.decode(string: value)
				if streamId > 1 { // at least the second request
					inc = !(lowered == "apns-id" || lowered == "apns-expiration")
				}
				try encoder.encodeHeader(out: headerBytes, name: n, value: v, sensitive: false, incrementalIndexing: inc)
			}

		} catch {
			callback(nil, "Header encoding exception \(error)")
			return
		}
		let hasData = request.postBodyBytes?.count > 0
		let frame = HTTP2Frame(length: UInt32(headerBytes.data.count), type: HTTP2_HEADERS, flags: HTTP2_END_HEADERS | (hasData ? 0 : HTTP2_END_STREAM), streamId: streamId, payload: headerBytes.data)
		self.writeHTTP2Frame(frame) { [weak self]
			b in

			guard b else {
				callback(nil, "Unable to write frame")
				return
			}
			guard let s = self else {
				callback(nil, nil)
				return
			}
			s.streams[streamId] = .open
			if hasData {

				let frame2 = HTTP2Frame(length: UInt32(request.postBodyBytes?.count ?? 0), type: HTTP2_DATA, flags: HTTP2_END_STREAM, streamId: streamId, payload: request.postBodyBytes)
				s.writeHTTP2Frame(frame2) { [weak self]
					b in

					guard let s = self else {
						callback(nil, nil)
						return
					}

					s.awaitResponse(streamId: streamId, request: request, callback: callback)
				}

			} else {
				s.awaitResponse(streamId: streamId, request: request, callback: callback)
			}
		}
	}

	func completeConnect(_ callback: (Bool) -> ()) {
		net.write(string: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") {
			wrote in

			let settings = HTTP2Frame(length: 0, type: HTTP2_SETTINGS, flags: 0, streamId: 0, payload: nil)
			self.writeHTTP2Frame(settings) { [weak self]
				b in

				if b {
					self?.startReadThread()
				}
				callback(b)
			}
		}
	}

	func bytesToHeader(_ b: [UInt8]) -> HTTP2Frame {
		let payloadLength = (UInt32(b[0]) << 16) + (UInt32(b[1]) << 8) + UInt32(b[2])

		let type = b[3]
		let flags = b[4]
		var sid: UInt32 = UInt32(b[5])
		sid <<= 8
		sid += UInt32(b[6])
		sid <<= 8
		sid += UInt32(b[7])
		sid <<= 8
		sid += UInt32(b[8])

		sid &= ~0x80000000

		return HTTP2Frame(length: payloadLength, type: type, flags: flags, streamId: sid, payload: nil)
	}

	func readHTTP2Frame(timeout time: Double, callback: (HTTP2Frame?) -> ()) {
		let net = self.net
		net.readBytesFully(count: 9, timeoutSeconds: time) {
			bytes in

			if let b = bytes {

				var header = self.bytesToHeader(b)

				if header.length > 0 {
					net.readBytesFully(count: Int(header.length), timeoutSeconds: time) {
						bytes in

						header.payload = bytes

						callback(header)
					}
				} else {
					callback(header)
				}

			} else {
				callback(nil)
			}
		}
	}

	func writeHTTP2Frame(_ frame: HTTP2Frame, callback: (Bool) -> ()) {
		if !net.isValid {
			callback(false)
		} else if !net.writeFully(bytes: frame.headerBytes()) {
			callback(false)
		} else {
//			print("Wrote frame \(frame.typeStr) \(frame.flagsStr) \(frame.streamId)")
			if let p = frame.payload {
				callback(net.writeFully(bytes: p))
			} else {
				callback(true)
			}
		}
	}

	func encodeHeaders(headers: [(String, String)]) -> Bytes {
		let b = Bytes()
		let encoder = HPACKEncoder(maxCapacity: 4096)
		for header in headers {
			let n = UTF8Encoding.decode(string: header.0)
			let v = UTF8Encoding.decode(string: header.1)
			do {
				try encoder.encodeHeader(out: b, name: n, value: v, sensitive: false)
			} catch {
				self.close()
				break
			}
		}
		return b
	}

	func decodeHeaders(from frm: Bytes, endPosition: Int, listener: HeaderListener) {
		let decoder = HPACKDecoder()
		do {
			try decoder.decode(input: frm, headerListener: listener)
		} catch {
			self.close()
		}
	}
}
