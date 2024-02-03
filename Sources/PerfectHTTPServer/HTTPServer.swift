//
//	HTTPServer.swift
//	PerfectLib
//
//	Created by Kyle Jessup on 2015-10-23.
//	Copyright (C) 2015 PerfectlySoft, Inc.
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
import PerfectThread
import PerfectLib
import PerfectHTTP

#if os(Linux)
	import SwiftGlibc
	import LinuxBridge
#else
	import Darwin
#endif

/// Stand-alone HTTP server.
public class HTTPServer: ServerInstance {
    // swiftlint:disable type_name
	public typealias certKeyPair = (sslCert: String, sslKey: String)
	private var net: NetTCP?
	/// The directory in which web documents are sought.
	/// Setting the document root will add a default URL route which permits
	/// static files to be served from within.
	public var documentRoot = "./webroot" { // Given a "safe" default
		didSet {
			do {
				let dir = Dir(documentRoot)
				if !dir.exists {
					try Dir(documentRoot).create()
				}
				self.routes.add(method: .get, uri: "/**", handler: { request, response in
					StaticFileHandler(documentRoot: request.documentRoot).handleRequest(request: request, response: response)
				})
			} catch {
				Log.terminal(message: "The document root \(documentRoot) could not be created.")
			}
		}
	}
	/// The port on which the server is listening.
	public var serverPort: UInt16 = 0
	/// The local address on which the server is listening. The default of 0.0.0.0 indicates any address.
	public var serverAddress = "0.0.0.0"
	/// Switch to user after binding port
	public var runAsUser: String?
	/// The canonical server name.
	/// This is important if utilizing the `HTTPRequest.serverName` property.
	public var serverName = ""
	public var ssl: certKeyPair?
	public var caCert: String?
	public var certVerifyMode: OpenSSLVerifyMode?
	public var cipherList = [
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
		"ECDHE-ECDSA-AES256-SHA"]

	var requestFilters = [[HTTPRequestFilter]]()
	var responseFilters = [[HTTPResponseFilter]]()

	/// Routing support
	private var routes = Routes()
	private var routeNavigator: RouteNavigator?

	public enum ALPNSupport: String {
		case http11 = "http/1.1", http2 = "h2"
	}
	public var alpnSupport = [ALPNSupport.http11]

	/// Initialize the server object.
	public init() {}

	@available(*, deprecated, message: "Set documentRoot directly")
	public init(documentRoot: String) {
		self.documentRoot = documentRoot
	}

	/// Add the Routes to this server.
	public func addRoutes(_ routes: Routes) {
		self.routes.add(routes)
	}

	/// Set the request filters. Each is provided along with its priority.
	/// The filters can be provided in any order. High priority filters will be sorted above lower priorities.
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
	/// The filters can be provided in any order. High priority filters will be sorted above lower priorities.
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

	@available(*, deprecated, message: "Set serverPort and call start()")
	public func start(port: UInt16, bindAddress: String = "0.0.0.0") throws {
		self.serverPort = port
		self.serverAddress = bindAddress
		try self.start()
	}

	@available(*, deprecated, message: "Set serverPort and ssl directly then call start()")
	public func start(port: UInt16, sslCert: String, sslKey: String, bindAddress: String = "0.0.0.0") throws {
		self.serverPort = port
		self.serverAddress = bindAddress
		self.ssl = (sslCert: sslCert, sslKey: sslKey)
		try self.start()
	}

	/// Bind the server to the designated address/port
	public func bind() throws {
		if let (cert, key) = ssl {
			let socket = NetTCPSSL()
			try socket.bind(port: serverPort, address: serverAddress)
			socket.cipherList = self.cipherList
			if let verifyMode = certVerifyMode,
				let cert = caCert,
				verifyMode != .sslVerifyNone {

				guard socket.setClientCA(path: cert, verifyMode: verifyMode) else {
					let code = Int32(socket.errorCode())
					throw PerfectError.networkError(code, "Error setting clientCA : \(socket.errorStr(forCode: code))")
				}
			}
			let sourcePrefix = "-----BEGIN"
			if cert.hasPrefix(sourcePrefix) {
				guard socket.useCertificateChain(cert: cert) else {
					let code = Int32(socket.errorCode())
					throw PerfectError.networkError(code, "Error setting certificate chain file: \(socket.errorStr(forCode: code))")
				}
			} else {
				guard socket.useCertificateChainFile(cert: cert) else {
					let code = Int32(socket.errorCode())
					throw PerfectError.networkError(code, "Error setting certificate chain file: \(socket.errorStr(forCode: code))")
				}
			}
			if key.hasPrefix(sourcePrefix) {
				guard socket.usePrivateKey(cert: key) else {
					let code = Int32(socket.errorCode())
					throw PerfectError.networkError(code, "Error setting private key file: \(socket.errorStr(forCode: code))")
				}
			} else {
				guard socket.usePrivateKeyFile(cert: key) else {
					let code = Int32(socket.errorCode())
					throw PerfectError.networkError(code, "Error setting private key file: \(socket.errorStr(forCode: code))")
				}
			}
			guard socket.checkPrivateKey() else {
				let code = Int32(socket.errorCode())
				throw PerfectError.networkError(code, "Error validating private key file: \(socket.errorStr(forCode: code))")
			}
			socket.enableALPN(protocols: self.alpnSupport.map { $0.rawValue })
			self.net = socket
		} else {
			let net = NetTCP()
			try net.bind(port: serverPort, address: serverAddress)
			self.net = net
		}
	}

	/// Start the server. Does not return until the server terminates.
	public func start() throws {
		if nil == self.net {
			try bind()
		}
		guard let net = self.net else {
			throw PerfectError.networkError(-1, "The socket was not bound.")
		}
		let witess = (net is NetTCPSSL) ? "HTTPS" : "HTTP"
		Log.info(message: "Starting \(witess) server \(self.serverName) on \(self.serverAddress):\(self.serverPort)")
		try self.startInner()
	}

	func accepted(net: NetTCP) {
		netHandleQueue.async {
			self.handleConnection(net)
		}
	}

	private func startInner() throws {
		// 1.0 compatability ONLY
		if let compatRoutes = compatRoutes {
			self.addRoutes(compatRoutes)
		}

		guard let sock = self.net else {
			Log.terminal(message: "Server could not be started. Socket was not initialized.")
		}
		if let runAs = self.runAsUser {
			try PerfectServer.switchTo(userName: runAs)
		}
		sock.listen()
		defer { sock.close() }
		self.serverAddress = sock.localAddress?.host ?? ""
		self.routeNavigator = self.routes.navigator
		sock.forEachAccept { [weak self] net in
			guard let net = net else {
				return
			}
			self?.accepted(net: net)
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
		var flag = 1
		_ = setsockopt(net.fd.fd, Int32(IPPROTO_TCP), TCP_NODELAY, &flag, UInt32(MemoryLayout<Int32>.size))
		if let netSSL = net as? NetTCPSSL, let neg = netSSL.alpnNegotiated, neg == ALPNSupport.http2.rawValue {
			_ = HTTP2PrefaceValidator(net, timeoutSeconds: 5.0) {
				_ = HTTP2Session(net, server: self)
			}
			return
		}
		let req = HTTP11Request(connection: net)
		req.serverName = self.serverName
		req.readRequest { [weak self] status in
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
		let response = HTTP11Response(request: request, filters: responseFilters.isEmpty ? nil : responseFilters.makeIterator())
		if response.isKeepAlive {
			response.completedCallback = { [weak self] in
				if let `self` = self {
					netHandleQueue.async {
						self.handleConnection(net)
					}
				}
			}
		}
		let oldCompletion = response.completedCallback
		response.completedCallback = {
			response.completedCallback = nil
			response.flush { ok in
				guard ok else {
					net.close()
					return
				}
				if let cb = oldCompletion {
					cb()
				}
			}
		}
		filterAndRun(request: request, response: response)
	}

	func filterAndRun(request: HTTPRequest, response: HTTPResponse) {
		if requestFilters.isEmpty {
			routeRequest(request, response: response)
		} else {
			filterRequest(request, response: response, allFilters: requestFilters.makeIterator())
		}
	}

	private func filterRequest(_ request: HTTPRequest, response: HTTPResponse, allFilters: IndexingIterator<[[HTTPRequestFilter]]>) {
		var filters = allFilters
		if let prioFilters = filters.next() {
			filterRequest(request, response: response, allFilters: filters, prioFilters: prioFilters.makeIterator())
		} else {
			routeRequest(request, response: response)
		}
	}

	private func filterRequest(_ request: HTTPRequest, response: HTTPResponse,
	                           allFilters: IndexingIterator<[[HTTPRequestFilter]]>,
	                           prioFilters: IndexingIterator<[HTTPRequestFilter]>) {
		var prioFilters = prioFilters
		guard let filter = prioFilters.next() else {
			return filterRequest(request, response: response, allFilters: allFilters)
		}
		filter.filter(request: request, response: response) { result in
			switch result {
			case .continue(let req, let res):
				self.filterRequest(req, response: res, allFilters: allFilters, prioFilters: prioFilters)
			case .execute(let req, let res):
				self.filterRequest(req, response: res, allFilters: allFilters)
			case .halt(_, let res):
				res.completed()
			}
		}
	}

	private func routeRequest(_ request: HTTPRequest, response: HTTPResponse) {
		if let nav = routeNavigator,
				let handlers = nav.findHandlers(pathComponents: request.pathComponents, webRequest: request) {
			// cheating
			if let resp = response as? HTTP2Response {
				resp.handlers = handlers.makeIterator()
				resp.next()
			} else if let resp = response as? HTTP11Response {
				resp.handlers = handlers.makeIterator()
				resp.next()
			} else {
				handlers.last?(request, response)
			}
		} else {
			response.status = .notFound
			response.appendBody(string: "The file \(request.path) was not found.")
			response.completed()
		}
	}
}
