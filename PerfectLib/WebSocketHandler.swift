//
//  WebSocketHandler.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2016-01-06.
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

#if os(Linux)
import SwiftGlibc
import LinuxBridge
private let UINT16_MAX = UInt(0xFFFF)
#endif

private let smallPayloadSize = 126

/// This class represents the communications channel for a WebSocket session.
public class WebSocket {

	/// The various types of WebSocket messages.
	public enum OpcodeType: UInt8 {
		case Continuation = 0x0, Text = 0x1, Binary = 0x2, Close = 0x8, Ping = 0x9, Pong = 0xA, Invalid
	}

	private struct Frame {
		let fin: Bool
		let rsv1: Bool
		let rsv2: Bool
		let rsv3: Bool
		let opCode: OpcodeType
		let bytesPayload: [UInt8]

		var stringPayload: String? {
			return UTF8Encoding.encode(self.bytesPayload)
		}
	}

	private let connection: WebConnection
	/// The read timeout, in seconds. By default this is -1, which means no timeout.
	public var readTimeoutSeconds: Double = -1.0
	private var socket: NetTCP { return self.connection.connection }
	/// Indicates if the socket is still likely connected or if it has been closed.
	public var isConnected: Bool { return self.socket.fd.isValid }
	private var nextIsContinuation = false
	private let readBuffer = Bytes()

	init(connection: WebConnection) {
		self.connection = connection
	}

	/// Close the connection.
	public func close() {
		if self.socket.fd.isValid {

			self.sendMessage(.Close, bytes: [UInt8](), final: true) {
				self.socket.close()
			}
		}
	}

	private func clearFrame() {
		let position = self.readBuffer.position
		self.readBuffer.data.removeFirst(position)
		self.readBuffer.position = 0
	}

	private func fillFrame() -> Frame? {

		guard self.readBuffer.availableExportBytes >= 2 else {
			return nil
		}
		// we know we potentially have a valid frame here

		// for to be resetting the position if we don't have a valid frame yet
		let oldPosition = self.readBuffer.position

		let byte1 = self.readBuffer.export8Bits()
		let byte2 = self.readBuffer.export8Bits()

		let fin = (byte1 & 0x80) != 0
		let rsv1 = (byte1 & 0x40) != 0
		let rsv2 = (byte1 & 0x20) != 0
		let rsv3 = (byte1 & 0x10) != 0
		let opcode = OpcodeType(rawValue: byte1 & 0xF) ?? .Invalid

		let maskBit = (byte2 & 0x80) != 0

		guard maskBit else {
			self.close()
			return nil
		}

		var unmaskedLength = Int(byte2 ^ 0x80)

		if unmaskedLength == smallPayloadSize {

			if self.readBuffer.availableExportBytes >= 2 {
				unmaskedLength = Int(ntohs(self.readBuffer.export16Bits()))
			}

		} else if unmaskedLength > smallPayloadSize {

			if self.readBuffer.availableExportBytes >= 8 {
				unmaskedLength = Int(ntohll(self.readBuffer.export64Bits()))
			}

		} // else small payload

		if self.readBuffer.availableExportBytes >= 4 {

			let maskingKey = self.readBuffer.exportBytes(4)

			if self.readBuffer.availableExportBytes >= unmaskedLength {

				var exported = self.readBuffer.exportBytes(unmaskedLength)
				for i in 0..<exported.count {
					exported[i] = exported[i] ^ maskingKey[i % 4]
				}
				self.clearFrame()
				return Frame(fin: fin, rsv1: rsv1, rsv2: rsv2, rsv3: rsv3, opCode: opcode, bytesPayload: exported)
			}
		}

		self.readBuffer.position = oldPosition
		return nil
	}

	func fillBuffer(demand: Int, completion: (Bool) -> ()) {
		self.socket.readBytesFully(demand, timeoutSeconds: self.readTimeoutSeconds) {
			[weak self] (b:[UInt8]?) -> () in
			if let b = b {
				self?.readBuffer.data.appendContentsOf(b)
			}
			completion(b != nil)
		}
	}

	func fillBufferSome(suggestion: Int, completion: () -> ()) {
		self.socket.readSomeBytes(suggestion) {
			[weak self] (b:[UInt8]?) -> () in
			if let b = b {
				self?.readBuffer.data.appendContentsOf(b)
			}
			completion()
		}
	}

	private func readFrame(completion: (Frame?) -> ()) {
		if let frame = self.fillFrame() {

			switch frame.opCode {
			// check for and handle ping/pong
			case .Ping:
				self.sendMessage(.Pong, bytes: frame.bytesPayload, final: true) {
					self.readFrame(completion)
				}
				return
			// check for and handle close
			case .Close:
				self.close()
				return completion(nil)
			default:
				return completion(frame)
			}
		}
		self.fillBuffer(1) {
			b in
			guard b != false else {
				return completion(nil)
			}
			self.fillBufferSome(1024 * 32) { // some arbitrary read-ahead amount
				self.readFrame(completion)
			}
		}
	}

	/// Read string data from the client.
	public func readStringMessage(continuation: (String?, opcode: OpcodeType, final: Bool) -> ()) {
		self.readFrame {
			frame in
			continuation(frame?.stringPayload, opcode: frame?.opCode ?? .Invalid, final: frame?.fin ?? true)
		}
	}

	/// Read binary data from the client.
	public func readBytesMessage(continuation: ([UInt8]?, opcode: OpcodeType, final: Bool) -> ()) {
		self.readFrame {
			frame in
			continuation(frame?.bytesPayload, opcode: frame?.opCode ?? .Invalid, final: frame?.fin ?? true)
		}
	}

	/// Send binary data to thew client.
	public func sendBinaryMessage(bytes: [UInt8], final: Bool, completion: () -> ()) {
		self.sendMessage(.Binary, bytes: bytes, final: final, completion: completion)
	}

	/// Send string data to the client.
	public func sendStringMessage(string: String, final: Bool, completion: () -> ()) {
		self.sendMessage(.Text, bytes: UTF8Encoding.decode(string), final: final, completion: completion)
	}

	/// Send a "pong" message to the client.
	public func sendPong(completion: () -> ()) {
		self.sendMessage(.Pong, bytes: [UInt8](), final: true, completion: completion)
	}

	/// Send a "ping" message to the client.
	/// Expect a "pong" message to follow.
	public func sendPing(completion: () -> ()) {
		self.sendMessage(.Ping, bytes: [UInt8](), final: true, completion: completion)
	}

	private func sendMessage(opcode: OpcodeType, bytes: [UInt8], final: Bool, completion: () -> ()) {
		let sendBuffer = Bytes()

		let byte1 = UInt8(final ? 0x80 : 0x0) | (self.nextIsContinuation ? 0 : opcode.rawValue)

		self.nextIsContinuation = !final

		sendBuffer.import8Bits(byte1)

		let payloadSize = bytes.count
		if payloadSize < smallPayloadSize {

			let byte2 = UInt8(payloadSize)

			sendBuffer.import8Bits(byte2)

		} else if payloadSize <= Int(UINT16_MAX) {

			sendBuffer.import8Bits(UInt8(smallPayloadSize))
				.import16Bits(htons(UInt16(payloadSize)))

		} else {

			sendBuffer.import8Bits(UInt8(1+smallPayloadSize))
				.import64Bits(htonll(UInt64(payloadSize)))

		}
		sendBuffer.importBytes(bytes)
		self.socket.writeBytes(sendBuffer.data) {
			_ in
			completion()
		}
	}
}

/// The protocol that all WebSocket handlers must implement.
public protocol WebSocketSessionHandler {

	/// Optionally indicate the name of the protocol the handler implements.
	/// If this has a valid, the protocol name will be validated against what the client is requesting.
	var socketProtocol: String? { get }
	/// This function is called once the WebSocket session has been initiated.
	func handleSession(request: WebRequest, socket: WebSocket)

}

private let acceptableProtocolVersions = [13]
private let webSocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

/// This request handler accepts WebSocket requests from client.
/// It will initialize the session and then deliver it to the `WebSocketSessionHandler`.
public class WebSocketHandler : RequestHandler {

	public typealias HandlerProducer = (request: WebRequest, protocols: [String]) -> WebSocketSessionHandler?

	private let handlerProducer: HandlerProducer

	public init(handlerProducer: HandlerProducer) {
		self.handlerProducer = handlerProducer
	}

	public func handleRequest(request: WebRequest, response: WebResponse) {

		guard let upgrade = request.header("Upgrade"),
			connection = request.header("Connection"),
			secWebSocketKey = request.header("Sec-WebSocket-Key"),
			secWebSocketVersion = request.header("Sec-WebSocket-Version")
			where upgrade.lowercaseString == "websocket" && connection.lowercaseString == "upgrade" else {

				response.setStatus(400, message: "Bad Request")
				response.requestCompletedCallback()
				return
		}

		guard acceptableProtocolVersions.contains(Int(secWebSocketVersion) ?? 0) else {
			response.setStatus(400, message: "Bad Request")
			response.addHeader("Sec-WebSocket-Version", value: "\(acceptableProtocolVersions[0])")
			response.appendBodyString("WebSocket protocol version \(secWebSocketVersion) not supported. Supported protocol versions are: \(acceptableProtocolVersions.map { String($0) }.joinWithSeparator(","))")
			response.requestCompletedCallback()
			return
		}

		let secWebSocketProtocol = request.header("Sec-WebSocket-Protocol") ?? ""
		let protocolList = secWebSocketProtocol.characters.split(",").flatMap {
			i -> String? in
			var s = String(i)
			while s.characters.count > 0 && s.characters[s.characters.startIndex] == " " {
				s.removeAtIndex(s.startIndex)
			}
			return s.characters.count > 0 ? s : nil
		}

		guard let handler = self.handlerProducer(request: request, protocols: protocolList) else {
			response.setStatus(400, message: "Bad Request")
			response.appendBodyString("WebSocket protocols not supported.")
			response.requestCompletedCallback()
			return
		}

		response.requestCompletedCallback = {} // this is no longer a normal request, eligible for keep-alive

		response.setStatus(101, message: "Switching Protocols")
		response.addHeader("Upgrade", value: "websocket")
		response.addHeader("Connection", value: "Upgrade")
		response.addHeader("Sec-WebSocket-Accept", value: self.base64((secWebSocketKey + webSocketGUID).utf8.sha1))

		if let chosenProtocol = handler.socketProtocol {
			response.addHeader("Sec-WebSocket-Protocol", value: chosenProtocol)
		}

		for (key, value) in response.headersArray {
			response.connection.writeHeaderLine(key + ": " + value)
		}
		response.connection.writeBodyBytes([UInt8]())

		handler.handleSession(request, socket: WebSocket(connection: response.connection))
	}

	private func base64(a: [UInt8]) -> String {
		let bio = BIO_push(BIO_new(BIO_f_base64()), BIO_new(BIO_s_mem()))

		BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL)
		BIO_write(bio, a, Int32(a.count))
		BIO_ctrl(bio, BIO_CTRL_FLUSH, 0, nil)

		var mem = UnsafeMutablePointer<BUF_MEM>()
		BIO_ctrl(bio, BIO_C_GET_BUF_MEM_PTR, 0, &mem)
		BIO_ctrl(bio, BIO_CTRL_SET_CLOSE, Int(BIO_NOCLOSE), nil)
		BIO_free_all(bio)

		let txt = UnsafeMutablePointer<UInt8>(mem.memory.data)
		let ret = UTF8Encoding.encode(GenerateFromPointer(from: txt, count: mem.memory.length))
		free(mem.memory.data)
		return ret
	}
}

import OpenSSL

extension String.UTF8View {
	var sha1: [UInt8] {
		let bytes = UnsafeMutablePointer<UInt8>.alloc(Int(SHA_DIGEST_LENGTH))
		defer { bytes.destroy() ; bytes.dealloc(Int(SHA_DIGEST_LENGTH)) }

		SHA1(Array<UInt8>(self), (self.count), bytes)

		var r = [UInt8]()
		for idx in 0..<Int(SHA_DIGEST_LENGTH) {
			r.append(bytes[idx])
		}
		return r
	}
}
