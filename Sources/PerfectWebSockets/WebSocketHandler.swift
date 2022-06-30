//
//  WebSocketHandler.swift
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

import PerfectNet
import PerfectLib
import PerfectHTTP

#if os(Linux)
import SwiftGlibc
import LinuxBridge
private let UINT16_MAX = UInt(0xFFFF)
#else
import Darwin
#endif

import COpenSSL

private let smallPayloadSize = 126

/// This class represents the communications channel for a WebSocket session.
public class WebSocket: Equatable {

	/// The various types of WebSocket messages.
	public enum OpcodeType: UInt8 {
        /// Continuation op code
		case continuation = 0x0,
        /// Text data indicator
        text = 0x1,
        /// Binary data indicator
        binary = 0x2,
        /// Close indicator
        close = 0x8,
        /// Ping message
        ping = 0x9,
        /// Ping response message
        pong = 0xA,
        /// Invalid op code
        invalid
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

	/// The read timeout, in seconds. By default this is -1, which means no timeout.
	public var readTimeoutSeconds: Double = NetEvent.noTimeout

    /// Indicates if the socket is still likely connected or if it has been closed.
	public var isConnected: Bool { return self.socket.isValid }
    private let socket: NetTCP
    private var nextIsContinuation = false
	private let readBuffer = Bytes()

    init(socket: NetTCP) {
		self.socket = socket
	}

	/// Close the connection.
	public func close() {
		if self.socket.isValid {
			self.sendMessage(opcode: .close, bytes: [UInt8](), final: true) {
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
		let opcode = OpcodeType(rawValue: byte1 & 0xF) ?? .invalid
		let maskBit = (byte2 & 0x80) != 0

		guard maskBit else {
			self.close()
			return nil
		}

		var unmaskedLength = Int(byte2 ^ 0x80)
		if unmaskedLength == smallPayloadSize {
			if self.readBuffer.availableExportBytes >= 2 {
				unmaskedLength = Int(self.readBuffer.export16Bits().netToHost)
			}
		} else if unmaskedLength > smallPayloadSize {
			if self.readBuffer.availableExportBytes >= 8 {
				unmaskedLength = Int(self.readBuffer.export64Bits().netToHost)
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

	func fillBuffer(demand demnd: Int, completion: @escaping (Bool) -> ()) {
		self.socket.readBytesFully(count: demnd, timeoutSeconds: self.readTimeoutSeconds) { [weak self] (b: [UInt8]?) -> () in
			if let b = b {
				self?.readBuffer.data.append(contentsOf: b)
			}
			completion(b != nil)
		}
	}

	func fillBufferSome(suggestion suggest: Int, completion: @escaping () -> ()) {
		self.socket.readSomeBytes(count: suggest) { [weak self] (b: [UInt8]?) -> () in
			if let b = b {
				self?.readBuffer.data.append(contentsOf: b)
			}
			completion()
		}
	}

	private func readFrame(completion comp: @escaping (Frame?) -> ()) {
		if let frame = self.fillFrame() {
			switch frame.opCode {
			// check for and handle ping/pong
			case .ping:
				self.sendMessage(opcode: .pong, bytes: frame.bytesPayload, final: true) {
					self.readFrame(completion: comp)
				}
			// check for and handle close
			case .close:
				self.close()
				comp(nil)
			default:
				comp(frame)
			}
        } else {
            self.fillBuffer(demand: 1) { b in
                guard b else {
                    return comp(nil)
                }
                self.fillBufferSome(suggestion: 1024 * 32) { // some arbitrary read-ahead amount
                    self.readFrame(completion: comp)
                }
            }
        }
	}

	/// Read string data from the client.
	public func readStringMessage(continuation: @escaping (String?, _ opcode: OpcodeType, _ final: Bool) -> ()) {
		self.readFrame { frame in
			continuation(frame?.stringPayload, frame?.opCode ?? .invalid, frame?.fin ?? true)
		}
	}

	/// Read binary data from the client.
	public func readBytesMessage(continuation: @escaping ([UInt8]?, _ opcode: OpcodeType, _ final: Bool) -> ()) {
		self.readFrame { frame in
			continuation(frame?.bytesPayload, frame?.opCode ?? .invalid, frame?.fin ?? true)
		}
	}

	/// Send binary data to thew client.
	public func sendBinaryMessage(bytes: [UInt8], final: Bool, completion: @escaping () -> ()) {
		self.sendMessage(opcode: .binary, bytes: bytes, final: final, completion: completion)
	}

	/// Send string data to the client.
	public func sendStringMessage(string: String, final: Bool, completion: @escaping () -> ()) {
		self.sendMessage(opcode: .text, bytes: UTF8Encoding.decode(string: string), final: final, completion: completion)
	}

	/// Send a "pong" message to the client.
	public func sendPong(completion: @escaping () -> ()) {
		self.sendMessage(opcode: .pong, bytes: [UInt8](), final: true, completion: completion)
	}

	/// Send a "ping" message to the client.
	/// Expect a "pong" message to follow.
	public func sendPing(completion: @escaping () -> ()) {
		self.sendMessage(opcode: .ping, bytes: [UInt8](), final: true, completion: completion)
	}

	private func sendMessage(opcode op: OpcodeType, bytes: [UInt8], final: Bool, completion: @escaping () -> ()) {
		let sendBuffer = Bytes()

		let byte1 = UInt8(final ? 0x80 : 0x0) | (self.nextIsContinuation ? 0 : op.rawValue)

		self.nextIsContinuation = !final

		_ = sendBuffer.import8Bits(from: byte1)

		let payloadSize = bytes.count
		if payloadSize < smallPayloadSize {

			let byte2 = UInt8(payloadSize)

			_ = sendBuffer.import8Bits(from: byte2)

		} else if payloadSize <= Int(UINT16_MAX) {

			_ = sendBuffer.import8Bits(from: UInt8(smallPayloadSize))
				.import16Bits(from: UInt16(payloadSize).hostToNet)

		} else {

			_ = sendBuffer.import8Bits(from: UInt8(1+smallPayloadSize))
				.import64Bits(from: UInt64(payloadSize).hostToNet)

		}
		_ = sendBuffer.importBytes(from: bytes)
		self.socket.write(bytes: sendBuffer.data) { _ in
			completion()
		}
	}

	/// implement Equatable protocol
	public static func == (lhs: WebSocket, rhs: WebSocket) -> Bool {
		return lhs.socket == rhs.socket
	}
}

/// The protocol that all WebSocket handlers must implement.
public protocol WebSocketSessionHandler {

	/// Optionally indicate the name of the protocol the handler implements.
	/// If this has a valid, the protocol name will be validated against what the client is requesting.
	var socketProtocol: String? { get }
	/// This function is called once the WebSocket session has been initiated.
	func handleSession(request req: HTTPRequest, socket: WebSocket)

}

private let acceptableProtocolVersions = [13]
private let webSocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

/// This request handler accepts WebSocket requests from client.
/// It will initialize the session and then deliver it to the `WebSocketSessionHandler`.
public struct WebSocketHandler {

    /// Function which produces a WebSocketSessionHandler
	public typealias HandlerProducer = (_ request: HTTPRequest, _ protocols: [String]) -> WebSocketSessionHandler?

	private let handlerProducer: HandlerProducer

    /// Initialize WebSocketHandler with a handler producer function
	public init(handlerProducer: @escaping HandlerProducer) {
		self.handlerProducer = handlerProducer
	}

    /// Handle the request and negotiate the WebSocket session
	public func handleRequest(request: HTTPRequest, response: HTTPResponse) {

		guard let upgrade = request.header(.upgrade),
			let connection = request.header(.connection),
            let secWebSocketKey = request.header(.custom(name: "sec-websocket-key")),
			let secWebSocketVersion = request.header(.custom(name: "sec-websocket-version")), upgrade.lowercased() == "websocket" && connection.lowercased().contains(string: "upgrade") else {
				response.status = .badRequest
				return response.completed()
		}

		guard acceptableProtocolVersions.contains(Int(secWebSocketVersion) ?? 0) else {
			response.status = .badRequest
			response.addHeader(.custom(name: "Sec-WebSocket-Version"), value: "\(acceptableProtocolVersions[0])")
			response.appendBody(string: "WebSocket protocol version \(secWebSocketVersion) not supported. Supported protocol versions are: \(acceptableProtocolVersions)")
			return response.completed()
		}

		let secWebSocketProtocol = request.header(.custom(name: "sec-websocket-protocol")) ?? ""
		let protocolList = secWebSocketProtocol.split(separator: ",").compactMap { i -> String? in
			var s = String(i)
			while s.count > 0 && s[s.startIndex] == " " {
				s.remove(at: s.startIndex)
			}
			return s.count > 0 ? s : nil
		}

		guard let handler = self.handlerProducer(request, protocolList) else {
			response.status = .badRequest
			response.appendBody(string: "WebSocket protocols not supported.")
			response.completed()
			return
		}
		request.scratchPad["no-compression"] = true
		response.status = .switchingProtocols
		response.addHeader(.upgrade, value: "websocket")
		response.addHeader(.connection, value: "Upgrade")
		response.addHeader(.custom(name: "Sec-WebSocket-Accept"), value: self.base64((secWebSocketKey + webSocketGUID).utf8.sha1))

		if let chosenProtocol = handler.socketProtocol {
			response.addHeader(.custom(name: "Sec-WebSocket-Protocol"), value: chosenProtocol)
		}

        response.push { ok in
			guard ok else {
				request.connection.close()
				return
			}
			handler.handleSession(request: request, socket: WebSocket(socket: request.connection))
		}
	}

	private func base64(_ a: [UInt8]) -> String {
		let bio = BIO_push(BIO_new(BIO_f_base64()), BIO_new(BIO_s_mem()))

		BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL)
		BIO_write(bio, a, Int32(a.count))
		BIO_ctrl(bio, BIO_CTRL_FLUSH, 0, nil)

		var mem = UnsafeMutablePointer<BUF_MEM>(nil as OpaquePointer?)
		BIO_ctrl(bio, BIO_C_GET_BUF_MEM_PTR, 0, &mem)
		BIO_ctrl(bio, BIO_CTRL_SET_CLOSE, Int(BIO_NOCLOSE), nil)
		BIO_free_all(bio)

		guard let amem = mem else {
			return ""
		}
		guard let txt = UnsafeMutableRawPointer(amem.pointee.data)?.assumingMemoryBound(to: UInt8.self) else {
			return ""
		}
		let ret = UTF8Encoding.encode(generator: GenerateFromPointer(from: txt, count: amem.pointee.length))
		free(amem.pointee.data)
		return ret
	}
}

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
