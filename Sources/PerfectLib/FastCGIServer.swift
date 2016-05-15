//
//  FastCGIServer.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/6/15.
//	Copyright (C) 2015 PerfectlySoft, Inc.
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
#else
import Darwin
#endif

/// A server for the FastCGI protocol.
/// Listens for requests on either a named pipe or a TCP socket. Once started, it does not stop or return outside of a catastrophic error.
/// When a request is received, the server will instantiate a `WebRequest`/`WebResponse` pair and they will handle the remainder of the request.
public class FastCGIServer {

	private var net: NetTCP?

	/// Empty public initializer
	public init() {

	}

	/// Start the server on the indicated named pipe
	public func start(namedPipe name: String) throws {
		if access(name, F_OK) != -1 {
			// exists. remove it
			unlink(name)
		}
		let pipe = NetNamedPipe()
		pipe.initSocket()
		try pipe.bind(address: name)
		pipe.listen()
		chmod(name, mode_t(S_IRWXU|S_IRWXO|S_IRWXG))

		self.net = pipe

		defer { pipe.close() }

		print("Starting FastCGI server on named pipe "+name)

		self.start()
	}

	/// Start the server on the indicated TCP port and optional address
	public func start(port prt: UInt16, bindAddress: String = "0.0.0.0") throws {
		let socket = NetTCP()
		socket.initSocket()
		try socket.bind(port: prt, address: bindAddress)
		socket.listen()

		defer { socket.close() }

		print("Starting FastCGi server on \(bindAddress):\(prt)")

		self.start()
	}

	func start() {

		if let n = self.net {

			n.forEachAccept {
				[weak self] (net: NetTCP?) -> () in

				if let n = net {
					Threading.dispatchBlock {
						self?.handleConnection(net: n)
					}
				}
			}
		}
	}

	func handleConnection(net nt: NetTCP) {
		let fcgiReq = FastCGIRequest(net: nt)
		readRecord(fcgiReq: fcgiReq)
	}

	func readRecord(fcgiReq req: FastCGIRequest) {

		req.readRecord {
			[weak self] (r:FastCGIRecord?) -> () in

			guard let record = r else {
				req.connection.close()
				return // died. timed out. errorered
			}

			self?.handleRecord(fcgiReq: req, fcgiRecord: record)
		}

	}

	func handleRecord(fcgiReq req: FastCGIRequest, fcgiRecord: FastCGIRecord) {
		switch fcgiRecord.recType {

		case fcgiBeginRequest:
			// FastCGIBeginRequestBody UInt16 role, UInt8 flags
			let role: UInt16 = ntohs((UInt16(fcgiRecord.content![1]) << 8) | UInt16(fcgiRecord.content![0]))
			let flags: UInt8 = fcgiRecord.content![2]
			req.requestParams["L_FCGI_ROLE"] = String(role)
			req.requestParams["L_FCGI_FLAGS"] = String(flags)
			req.requestId = fcgiRecord.requestId
		case fcgiParams:
			if fcgiRecord.contentLength > 0 {

				let bytes = fcgiRecord.content!
				var idx = 0

				repeat {
					// sizes are either one byte or 4
					var sz = Int32(bytes[idx])
					idx += 1
					if (sz & 0x80) != 0 { // name length
						sz = (sz & 0x7f) << 24
						sz += (Int32(bytes[idx]) << 16)
						idx += 1
						sz += (Int32(bytes[idx]) << 8)
						idx += 1
						sz += Int32(bytes[idx])
						idx += 1
					}
					var vsz = Int32(bytes[idx])
					idx += 1
					if (vsz & 0x80) != 0 { // value length
						vsz = (vsz & 0x7f) << 24
						vsz += (Int32(bytes[idx]) << 16)
						idx += 1
						vsz += (Int32(bytes[idx]) << 8)
						idx += 1
						vsz += Int32(bytes[idx])
						idx += 1
					}
					if sz > 0 {
						let idx2 = Int(idx + sz)
						let name = UTF8Encoding.encode(bytes: bytes[idx..<idx2])
						let idx3 = idx2 + Int(vsz)
						let value = UTF8Encoding.encode(bytes: bytes[idx2..<idx3])

						req.requestParams[name] = value

						idx = idx3
					}
				} while idx < bytes.count

			}
		case fcgiStdin:
			if fcgiRecord.contentLength > 0 {
				req.putStdinData(fcgiRecord.content!)
			} else { // done initiating the request. run with it
				runRequest(req)
				return
			}

		case fcgiData:
			if fcgiRecord.contentLength > 0 {
				req.requestParams["L_FCGI_DATA"] = UTF8Encoding.encode(bytes: fcgiRecord.content!)
			}

		case fcgiXStdin:

			if Int(fcgiRecord.contentLength) == sizeof(UInt32) {

				let one = UInt32(fcgiRecord.content![0])
				let two = UInt32(fcgiRecord.content![1])
				let three = UInt32(fcgiRecord.content![2])
				let four = UInt32(fcgiRecord.content![3])

				let size = ntohl((four << 24) + (three << 16) + (two << 8) + one)

				readXStdin(fcgiReq: req, size: Int(size))
				return
			}

		default:
			print("Unhandled FastCGI record type \(fcgiRecord.recType)")

		}
		req.lastRecordType = fcgiRecord.recType
		readRecord(fcgiReq: req)
	}

	func readXStdin(fcgiReq req: FastCGIRequest, size: Int) {

		req.connection.readSomeBytes(count: size) {
			[weak self] (b:[UInt8]?) -> () in

			guard let bytes = b else {
				req.connection.close()
				return // died. timed out. errorered
			}

			req.putStdinData(bytes)

			let remaining = size - bytes.count
			if  remaining == 0 {
				req.lastRecordType = fcgiStdin
				self?.readRecord(fcgiReq: req)
			} else {
				self?.readXStdin(fcgiReq: req, size: remaining)
			}
		}
	}

	func runRequest(_ fcgiReq: FastCGIRequest) {

		let request = WebRequest(fcgiReq)
		let response = WebResponse(fcgiReq, request: request)

		response.respond {

			let status = response.appStatus

			let finalBytes = fcgiReq.makeEndRequestBody(requestId: Int(fcgiReq.requestId), appStatus: status, protocolStatus: fcgiRequestComplete)
			fcgiReq.write(bytes: finalBytes)
			fcgiReq.connection.close()
		}
	}
}
