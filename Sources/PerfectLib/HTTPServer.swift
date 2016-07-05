//
//  HTTPServer.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2015-10-23.
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

import PerfectNet
import PerfectThread

/// Stand-alone HTTP server. Provides the same WebConnection based interface as the FastCGI server.
public class HTTPServer {
	
	private var net: NetTCP?
	
	/// The directory in which web documents are sought.
	public let documentRoot: String
	/// The port on which the server is listening.
	public var serverPort: UInt16 = 0
	/// The local address on which the server is listening. The default of 0.0.0.0 indicates any local address.
	public var serverAddress = "0.0.0.0"
	/// Switch to user after binding port
    public var runAsUser: String?
    
	/// The canonical server name.
	/// This is important if utilizing the `WebRequest.serverName` "SERVER_NAME" variable.
	public var serverName = ""
	
	private var requestFilters = [[HTTPRequestFilter]]()
	private var responseFilters = [[HTTPResponseFilter]]()
	
	/// Initialize the server with a document root.
	/// - parameter documentRoot: The document root for the server.
	public init(documentRoot: String) {
		self.documentRoot = documentRoot
	}
	
	/// Set the request filters. Each is provided along with its priority.
	/// The filters can be provided in any order. High priority filters will be sorted able lower priorities.
	/// Filters of equal priority will maintain the order given here.
	@discardableResult
	public func setRequestFilters(_ request: [(HTTPRequestFilter, HTTPFilterPriority)]) -> HTTPServer {
		let high = request.filter { $0.1 == HTTPFilterPriority.high }.map { $0.0 },
		    med = request.filter { $0.1 == HTTPFilterPriority.medium }.map { $0.0 },
		    low = request.filter { $0.1 == HTTPFilterPriority.low }.map { $0.0 }
		if !high.isEmpty {
			requestFilters.append(high)
		}
		if !med.isEmpty {
			requestFilters.append(med)
		}
		if !low.isEmpty {
			requestFilters.append(low)
		}
		return self
	}
	
	/// Set the response filters. Each is provided along with its priority.
	/// The filters can be provided in any order. High priority filters will be sorted able lower priorities.
	/// Filters of equal priority will maintain the order given here.
	@discardableResult
	public func setResponseFilters(_ response: [(HTTPResponseFilter, HTTPFilterPriority)]) -> HTTPServer {
		let high = response.filter { $0.1 == HTTPFilterPriority.high }.map { $0.0 },
			med = response.filter { $0.1 == HTTPFilterPriority.medium }.map { $0.0 },
			low = response.filter { $0.1 == HTTPFilterPriority.low }.map { $0.0 }
		if !high.isEmpty {
			responseFilters.append(high)
		}
		if !med.isEmpty {
			responseFilters.append(med)
		}
		if !low.isEmpty {
			responseFilters.append(low)
		}
		return self
	}
	
	/// Start the server on the indicated TCP port and optional address.
	/// - parameter port: The port on which to bind.
	/// - parameter bindAddress: The local address on which to bind.
	public func start(port: UInt16, bindAddress: String = "0.0.0.0") throws {
		self.serverPort = port
		self.serverAddress = bindAddress
		let socket = NetTCP()
		socket.initSocket()
		try socket.bind(port: port, address: bindAddress)
        if let runAs = self.runAsUser {
            try PerfectServer.switchTo(userName: runAs)
        }
        Log.info(message: "Starting HTTP server on \(bindAddress):\(port) with document root \(self.documentRoot)")
		
		try self.startInner(socket: socket)
	}
	
	/// Start the server on the indicated TCP port and optional address.
	/// - parameter port: The port on which to bind.
	/// - parameter sslCert: The server SSL certificate file.
	/// - parameter sslKey: The server SSL key file.
	/// - parameter bindAddress: The local address on which to bind.
	public func start(port: UInt16, sslCert: String, sslKey: String, dhParams: String? = nil, bindAddress: String = "0.0.0.0") throws {
		
		self.serverPort = port
		self.serverAddress = bindAddress
		
		let socket = NetTCPSSL()
		socket.initSocket()
		
		let cipherList = [
			"ECDHE-ECDSA-AES256-GCM-SHA384",
			"ECDHE-ECDSA-AES128-GCM-SHA256",
			"ECDHE-ECDSA-AES256-CBC-SHA384",
			"ECDHE-ECDSA-AES256-CBC-SHA",
			"ECDHE-ECDSA-AES128-CBC-SHA256",
			"ECDHE-ECDSA-AES128-CBC-SHA",
			"ECDHE-RSA-AES256-GCM-SHA384",
			"ECDHE-RSA-AES128-GCM-SHA256",
			"ECDHE-RSA-AES256-CBC-SHA384",
			"ECDHE-RSA-AES128-CBC-SHA256",
			"ECDHE-RSA-AES128-CBC-SHA",
			
			"ECDHE-RSA-AES256-SHA384",
			"ECDHE-ECDSA-AES256-SHA384",
			"ECDHE-RSA-AES256-SHA",
			"ECDHE-ECDSA-AES256-SHA"
			/*,
			"SRP-DSS-AES-256-CBC-SHA",
			"SRP-RSA-AES-256-CBC-SHA",
			"SRP-AES-256-CBC-SHA",
			"DH-DSS-AES256-GCM-SHA384",
			"DHE-DSS-AES256-GCM-SHA384",
			"DH-RSA-AES256-GCM-SHA384",
			"DHE-RSA-AES256-GCM-SHA384",
			"DHE-RSA-AES256-SHA256",
			"DHE-DSS-AES256-SHA256",
			"DH-RSA-AES256-SHA256",
			"DH-DSS-AES256-SHA256",
			"DHE-RSA-AES256-SHA",
			"DHE-DSS-AES256-SHA",
			"DH-RSA-AES256-SHA",
			"DH-DSS-AES256-SHA",
			"DHE-RSA-CAMELLIA256-SHA",
			"DHE-DSS-CAMELLIA256-SHA",
			"DH-RSA-CAMELLIA256-SHA",
			"DH-DSS-CAMELLIA256-SHA",
			"ECDH-RSA-AES256-GCM-SHA384",
			"ECDH-ECDSA-AES256-GCM-SHA384",
			"ECDH-RSA-AES256-SHA384",
			"ECDH-ECDSA-AES256-SHA384",
			"ECDH-RSA-AES256-SHA",
			"ECDH-ECDSA-AES256-SHA",
			"AES256-GCM-SHA384",
			"AES256-SHA256",
			"AES256-SHA",
			"CAMELLIA256-SHA",
			"PSK-AES256-CBC-SHA",
			"ECDHE-RSA-AES128-SHA256",
			"ECDHE-ECDSA-AES128-SHA256",
			"ECDHE-RSA-AES128-SHA",
			"ECDHE-ECDSA-AES128-SHA",
			"SRP-DSS-AES-128-CBC-SHA",
			"SRP-RSA-AES-128-CBC-SHA",
			"SRP-AES-128-CBC-SHA",
			"DH-DSS-AES128-GCM-SHA256",
			"DHE-DSS-AES128-GCM-SHA256",
			"DH-RSA-AES128-GCM-SHA256",
			"DHE-RSA-AES128-GCM-SHA256",
			"DHE-RSA-AES128-SHA256",
			"DHE-DSS-AES128-SHA256",
			"DH-RSA-AES128-SHA256",
			"DH-DSS-AES128-SHA256",
			"DHE-RSA-AES128-SHA",
			"DHE-DSS-AES128-SHA",
			"DH-RSA-AES128-SHA",
			"DH-DSS-AES128-SHA",
			"DHE-RSA-SEED-SHA",
			"DHE-DSS-SEED-SHA",
			"DH-RSA-SEED-SHA",
			"DH-DSS-SEED-SHA",
			"DHE-RSA-CAMELLIA128-SHA",
			"DHE-DSS-CAMELLIA128-SHA",
			"DH-RSA-CAMELLIA128-SHA",
			"DH-DSS-CAMELLIA128-SHA",
			"ECDH-RSA-AES128-GCM-SHA256",
			"ECDH-ECDSA-AES128-GCM-SHA256",
			"ECDH-RSA-AES128-SHA256",
			"ECDH-ECDSA-AES128-SHA256",
			"ECDH-RSA-AES128-SHA",
			"ECDH-ECDSA-AES128-SHA",
			"AES128-GCM-SHA256",
			"AES128-SHA256",
			"AES128-SHA",
			"SEED-SHA",
			"CAMELLIA128-SHA",
			"IDEA-CBC-SHA",
			"PSK-AES128-CBC-SHA",
			"ECDHE-RSA-RC4-SHA",
			"ECDHE-ECDSA-RC4-SHA",
			"ECDH-RSA-RC4-SHA",
			"ECDH-ECDSA-RC4-SHA",
			"RC4-SHA",
			"RC4-MD5",
			"PSK-RC4-SHA",
			"ECDHE-RSA-DES-CBC3-SHA",
			"ECDHE-ECDSA-DES-CBC3-SHA",
			"SRP-DSS-3DES-EDE-CBC-SHA",
			"SRP-RSA-3DES-EDE-CBC-SHA",
			"SRP-3DES-EDE-CBC-SHA",
			"EDH-RSA-DES-CBC3-SHA",
			"EDH-DSS-DES-CBC3-SHA",
			"DH-RSA-DES-CBC3-SHA",
			"DH-DSS-DES-CBC3-SHA",
			"ECDH-RSA-DES-CBC3-SHA",
			"ECDH-ECDSA-DES-CBC3-SHA",
			"DES-CBC3-SHA",
			"PSK-3DES-EDE-CBC-SHA",
			"EDH-RSA-DES-CBC-SHA",
			"EDH-DSS-DES-CBC-SHA",
			"DH-RSA-DES-CBC-SHA",
			"DH-DSS-DES-CBC-SHA",
			"DES-CBC-SHA"
			*/
		]
		socket.cipherList = cipherList
		guard socket.useCertificateChainFile(cert: sslCert) else {
			let code = Int32(socket.errorCode())
			throw PerfectError.networkError(code, "Error setting certificate chain file: \(socket.errorStr(forCode: code))")
		}
		guard socket.usePrivateKeyFile(cert: sslKey) else {
			let code = Int32(socket.errorCode())
			throw PerfectError.networkError(code, "Error setting private key file: \(socket.errorStr(forCode: code))")
		}
		guard socket.checkPrivateKey() else {
			let code = Int32(socket.errorCode())
			throw PerfectError.networkError(code, "Error validating private key file: \(socket.errorStr(forCode: code))")
		}
		try socket.bind(port: port, address: bindAddress)
        if let runAs = self.runAsUser {
            try PerfectServer.switchTo(userName: runAs)
        }
        Log.info(message: "Starting HTTPS server on \(bindAddress):\(port) with document root \(self.documentRoot)")
		try self.startInner(socket: socket)
	}
	
	private func startInner(socket sock: NetTCP) throws {
		sock.listen()
		self.net = sock
		defer { sock.close() }
		self.start()
	}
	
	func start() {
		if let n = self.net {
			self.serverAddress = n.sockName().0
			n.forEachAccept {
				[weak self] net in
				if let net = net {
					Threading.dispatch {
						self?.handleConnection(net)
					}
				}
			}
		}
	}
	
	/// Stop the server by closing the accepting TCP socket. Calling this will cause the server to break out of the otherwise blocking `start` function.
	public func stop() {
		if let n = self.net {
			self.net = nil
			n.close()
		}
	}
	
	func handleConnection(_ net: NetTCP) {
		let req = HTTP11Request(connection: net)
		req.readRequest { [weak self]
            status in
			if case .ok = status {
				self?.runRequest(req)
			} else {
				net.close()
			}
		}
	}
	
	func runRequest(_ request: HTTP11Request) {
		request.documentRoot = self.documentRoot
		let net = request.connection
        // !FIX! check for upgrade to http/2
        // switch to HTTP2Request/HTTP2Response
        
		let response = HTTP11Response(request: request, filters: responseFilters.isEmpty ? nil : responseFilters.makeIterator())
        if response.isKeepAlive {
            response.completedCallback = { [weak self] in
                self?.handleConnection(net)
            }
        }
        let oldCompletion = response.completedCallback
        response.completedCallback = {
            response.completedCallback = nil
            response.flush {
                ok in
                guard ok else {
                    net.close()
                    return
                }
                if let cb = oldCompletion {
                    cb()
                }
            }
        }
		if requestFilters.isEmpty {
			HTTPServer.routeRequest(request, response: response)
		} else {
			HTTPServer.filterRequest(request, response: response, allFilters: requestFilters.makeIterator())
		}
	}
	
	private static func filterRequest(_ request: HTTPRequest, response: HTTPResponse, allFilters: IndexingIterator<[[HTTPRequestFilter]]>) {
		var filters = allFilters
		if let prioFilters = filters.next() {
			HTTPServer.filterRequest(request, response: response, allFilters: filters, prioFilters: prioFilters.makeIterator())
		} else {
			HTTPServer.routeRequest(request, response: response)
		}
	}
	
	private static func filterRequest(_ request: HTTPRequest, response: HTTPResponse,
	                                  allFilters: IndexingIterator<[[HTTPRequestFilter]]>,
	                                  prioFilters: IndexingIterator<[HTTPRequestFilter]>) {
		var prioFilters = prioFilters
		guard let filter = prioFilters.next() else {
			return HTTPServer.filterRequest(request, response: response, allFilters: allFilters)
		}
		filter.filter(request: request, response: response) {
			result in
			switch result {
			case .continue(let req, let res):
				HTTPServer.filterRequest(req, response: res, allFilters: allFilters, prioFilters: prioFilters)
			case .execute(let req, let res):
				HTTPServer.filterRequest(req, response: res, allFilters: allFilters)
			case .halt(_, let res):
				res.completed()
			}
		}
	}
	
	private static func routeRequest(_ req: HTTPRequest, response: HTTPResponse) {
		Routing.handleRequest(req, response: response)
	}
}
