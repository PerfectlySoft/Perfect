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

import OpenSSL

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
			return UTF8Encoding.encode(bytes: self.bytesPayload)
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

			self.sendMessage(opcode: .Close, bytes: [UInt8](), final: true) {
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

			let maskingKey = self.readBuffer.exportBytes(count: 4)

			if self.readBuffer.availableExportBytes >= unmaskedLength {

				var exported = self.readBuffer.exportBytes(count: unmaskedLength)
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

	func fillBuffer(demand demand: Int, completion: (Bool) -> ()) {
		self.socket.readBytesFully(count: demand, timeoutSeconds: self.readTimeoutSeconds) {
			[weak self] (b:[UInt8]?) -> () in
			if let b = b {
				self?.readBuffer.data.append(contentsOf: b)
			}
			completion(b != nil)
		}
	}

	func fillBufferSome(suggestion suggestion: Int, completion: () -> ()) {
		self.socket.readSomeBytes(count: suggestion) {
			[weak self] (b:[UInt8]?) -> () in
			if let b = b {
				self?.readBuffer.data.append(contentsOf: b)
			}
			completion()
		}
	}

	private func readFrame(completion completion: (Frame?) -> ()) {
		if let frame = self.fillFrame() {

			switch frame.opCode {
			// check for and handle ping/pong
			case .Ping:
				self.sendMessage(opcode: .Pong, bytes: frame.bytesPayload, final: true) {
					self.readFrame(completion: completion)
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
		self.fillBuffer(demand: 1) {
			b in
			guard b != false else {
				return completion(nil)
			}
			self.fillBufferSome(suggestion: 1024 * 32) { // some arbitrary read-ahead amount
				self.readFrame(completion: completion)
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
		self.sendMessage(opcode: .Binary, bytes: bytes, final: final, completion: completion)
	}

	/// Send string data to the client.
	public func sendStringMessage(string: String, final: Bool, completion: () -> ()) {
		self.sendMessage(opcode: .Text, bytes: UTF8Encoding.decode(string: string), final: final, completion: completion)
	}

	/// Send a "pong" message to the client.
	public func sendPong(completion: () -> ()) {
		self.sendMessage(opcode: .Pong, bytes: [UInt8](), final: true, completion: completion)
	}

	/// Send a "ping" message to the client.
	/// Expect a "pong" message to follow.
	public func sendPing(completion: () -> ()) {
		self.sendMessage(opcode: .Ping, bytes: [UInt8](), final: true, completion: completion)
	}

	private func sendMessage(opcode opcode: OpcodeType, bytes: [UInt8], final: Bool, completion: () -> ()) {
		let sendBuffer = Bytes()

		let byte1 = UInt8(final ? 0x80 : 0x0) | (self.nextIsContinuation ? 0 : opcode.rawValue)

		self.nextIsContinuation = !final

		sendBuffer.import8Bits(from: byte1)

		let payloadSize = bytes.count
		if payloadSize < smallPayloadSize {

			let byte2 = UInt8(payloadSize)

			sendBuffer.import8Bits(from: byte2)

		} else if payloadSize <= Int(UINT16_MAX) {

			sendBuffer.import8Bits(from: UInt8(smallPayloadSize))
				.import16Bits(from: htons(UInt16(payloadSize)))

		} else {

			sendBuffer.import8Bits(from: UInt8(1+smallPayloadSize))
				.import64Bits(from: htonll(UInt64(payloadSize)))

		}
		sendBuffer.importBytes(from: bytes)
		self.socket.write(bytes: sendBuffer.data) {
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
	func handleSession(request request: WebRequest, socket: WebSocket)

}

private let acceptableProtocolVersions = [13]
private let webSocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

/// This request handler accepts WebSocket requests from client.
/// It will initialize the session and then deliver it to the `WebSocketSessionHandler`.
public struct WebSocketHandler {

	public typealias HandlerProducer = (request: WebRequest, protocols: [String]) -> WebSocketSessionHandler?

	private let handlerProducer: HandlerProducer

	public init(handlerProducer: HandlerProducer) {
		self.handlerProducer = handlerProducer
	}

	public func handleRequest(request: WebRequest, response: WebResponse) {

		guard let upgrade = request.header(named: "Upgrade"),
			connection = request.header(named: "Connection"),
			secWebSocketKey = request.header(named: "Sec-WebSocket-Key"),
			secWebSocketVersion = request.header(named: "Sec-WebSocket-Version")
			where upgrade.lowercased() == "websocket" && connection.lowercased().contains(string: "upgrade") else {

				response.setStatus(code: 400, message: "Bad Request")
				response.requestCompleted()
				return
		}

		guard acceptableProtocolVersions.contains(Int(secWebSocketVersion) ?? 0) else {
			response.setStatus(code: 400, message: "Bad Request")
			response.addHeader(name: "Sec-WebSocket-Version", value: "\(acceptableProtocolVersions[0])")
			response.appendBody(string: "WebSocket protocol version \(secWebSocketVersion) not supported. Supported protocol versions are: \(acceptableProtocolVersions)")
			response.requestCompleted()
			return
		}

		let secWebSocketProtocol = request.header(named: "Sec-WebSocket-Protocol") ?? ""
		let protocolList = secWebSocketProtocol.characters.split(separator: ",").flatMap {
			i -> String? in
			var s = String(i)
			while s.characters.count > 0 && s.characters[s.characters.startIndex] == " " {
				s.remove(at: s.startIndex)
			}
			return s.characters.count > 0 ? s : nil
		}

		guard let handler = self.handlerProducer(request: request, protocols: protocolList) else {
			response.setStatus(code: 400, message: "Bad Request")
			response.appendBody(string: "WebSocket protocols not supported.")
			response.requestCompleted()
			return
		}

		response.requestCompleted = {} // this is no longer a normal request, eligible for keep-alive

		response.setStatus(code: 101, message: "Switching Protocols")
		response.addHeader(name: "Upgrade", value: "websocket")
		response.addHeader(name: "Connection", value: "Upgrade")
		response.addHeader(name: "Sec-WebSocket-Accept", value: self.base64((secWebSocketKey + webSocketGUID).utf8.sha1))

		if let chosenProtocol = handler.socketProtocol {
			response.addHeader(name: "Sec-WebSocket-Protocol", value: chosenProtocol)
		}

		for (key, value) in response.headersArray {
			response.connection.writeHeader(line: key + ": " + value)
		}
		response.connection.writeBody(bytes: [UInt8]())

		handler.handleSession(request: request, socket: WebSocket(connection: response.connection))
	}

	private func base64(_ a: [UInt8]) -> String {
		let bio = BIO_push(BIO_new(BIO_f_base64()), BIO_new(BIO_s_mem()))

		BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL)
		BIO_write(bio, a, Int32(a.count))
		BIO_ctrl(bio, BIO_CTRL_FLUSH, 0, nil)

		var mem: UnsafeMutablePointer<BUF_MEM>? = UnsafeMutablePointer<BUF_MEM>(nil)
		BIO_ctrl(bio, BIO_C_GET_BUF_MEM_PTR, 0, &mem)
		BIO_ctrl(bio, BIO_CTRL_SET_CLOSE, Int(BIO_NOCLOSE), nil)
		BIO_free_all(bio)

		guard let amem = mem else {
			return ""
		}
	#if swift(>=3.0)
		guard let txt = UnsafeMutablePointer<UInt8>(amem.pointee.data) else {
			return ""
		}
	#else
		let txt = UnsafeMutablePointer<UInt8>(amem.pointee.data)
		guard nil != txt else {
			return ""
		}
	#endif
		let ret = UTF8Encoding.encode(generator: GenerateFromPointer(from: txt, count: amem.pointee.length))
		free(amem.pointee.data)
		return ret
	}
}

extension String.UTF8View {
	var sha1: [UInt8] {
		let bytes = UnsafeMutablePointer<UInt8>.allocatingCapacity(Int(SHA_DIGEST_LENGTH))
		defer { bytes.deallocateCapacity(Int(SHA_DIGEST_LENGTH)) }

		SHA1(Array<UInt8>(self), (self.count), bytes)

		var r = [UInt8]()
		for idx in 0..<Int(SHA_DIGEST_LENGTH) {
			r.append(bytes[idx])
		}
		return r
	}
}
