//
//  HTTPServerEx.swift
//  PerfectHTTPServer
//
//  Created by Kyle Jessup on 2016-11-14.
//
//

import PerfectThread
import PerfectHTTP
import PerfectNet
import PerfectLib
import Foundation

public struct TLSConfiguration {
	public static var defaultCipherList = [
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

	public var certPath: String { return cert }
	public var keyPath: String? { return key }
	public let cert: String
	public let key: String?
	public let caCertPath: String?
	public let certVerifyMode: OpenSSLVerifyMode?
	public let cipherList: [String]
	public let alpnSupport: [HTTPServer.ALPNSupport]

	/// Initialize a new struct with the desired TLS settings.
	/// The `cert` and `key` parameters can be either a file path or the raw PEM data.
	public init(cert: String, key: String? = nil,
	            caCertPath: String? = nil, certVerifyMode: OpenSSLVerifyMode? = nil,
	            cipherList: [String] = TLSConfiguration.defaultCipherList,
	            alpnSupport: [HTTPServer.ALPNSupport] = [.http11]) {
		self.cert = cert
		self.key = key
		self.caCertPath = caCertPath
		self.certVerifyMode = certVerifyMode
		self.cipherList = cipherList
		self.alpnSupport = alpnSupport
	}

	public init(certPath: String, keyPath: String? = nil,
	            caCertPath: String? = nil, certVerifyMode: OpenSSLVerifyMode? = nil,
	            cipherList: [String] = TLSConfiguration.defaultCipherList,
	            alpnSupport: [HTTPServer.ALPNSupport] = [.http11]) {
		self.init(cert: certPath,
		          key: keyPath,
		          caCertPath: caCertPath,
		          certVerifyMode: certVerifyMode,
		          cipherList: cipherList,
		          alpnSupport: alpnSupport)
	}
}

private var processRunAs: String?

public extension HTTPServer {

	static func runAs(_ user: String) -> HTTPServer.Type {
		processRunAs = user
		return self
	}

	struct Server {
		public let name: String
		public let port: Int
		public let address: String
		public let routes: Routes
		public let requestFilters: [(HTTPRequestFilter, HTTPFilterPriority)]
		public let responseFilters: [(HTTPResponseFilter, HTTPFilterPriority)]
		public let tlsConfig: TLSConfiguration?

		var server: HTTPServer {
			let http = HTTPServer()
			http.serverName = name
			http.serverPort = UInt16(port)
			http.serverAddress = address
			http.addRoutes(routes)
			http.setRequestFilters(requestFilters)
			http.setResponseFilters(responseFilters)
			if let tls = tlsConfig {
				http.ssl = (tls.certPath, tls.keyPath ?? tls.certPath)
				http.caCert = tls.caCertPath
				http.certVerifyMode = tls.certVerifyMode
				http.cipherList = tls.cipherList
				http.alpnSupport = tls.alpnSupport
			}
			return http
		}

		init() {
			name = ""
			address = ""
			port = 0
			routes = .init()
			requestFilters = []
			responseFilters = []
			tlsConfig = nil
		}

		public init(name: String, address: String, port: Int, routes: Routes,
		            requestFilters: [(HTTPRequestFilter, HTTPFilterPriority)] = [],
		            responseFilters: [(HTTPResponseFilter, HTTPFilterPriority)] = []) {
			self.name = name
			self.address = address
			self.port = port
			self.routes = routes
			self.requestFilters = requestFilters
			self.responseFilters = responseFilters
			self.tlsConfig = nil
		}

		public init(tlsConfig: TLSConfiguration, name: String, address: String, port: Int, routes: Routes,
		            requestFilters: [(HTTPRequestFilter, HTTPFilterPriority)] = [],
		            responseFilters: [(HTTPResponseFilter, HTTPFilterPriority)] = []) {
			self.name = name
			self.address = address
			self.port = port
			self.routes = routes
			self.requestFilters = requestFilters
			self.responseFilters = responseFilters
			self.tlsConfig = tlsConfig

		}

		public init(name: String, port: Int, routes: Routes,
		            requestFilters: [(HTTPRequestFilter, HTTPFilterPriority)] = [],
		            responseFilters: [(HTTPResponseFilter, HTTPFilterPriority)] = []) {
			self.init(name: name, address: "::", port: port, routes: routes, requestFilters: requestFilters, responseFilters: responseFilters)
		}

		public init(tlsConfig: TLSConfiguration, name: String, port: Int, routes: Routes,
		            requestFilters: [(HTTPRequestFilter, HTTPFilterPriority)] = [],
		            responseFilters: [(HTTPResponseFilter, HTTPFilterPriority)] = []) {
			self.init(tlsConfig: tlsConfig, name: name, address: "::", port: port, routes: routes, requestFilters: requestFilters, responseFilters: responseFilters)
		}

		public static func server(name: String, port: Int, routes: Routes,
		                          requestFilters: [(HTTPRequestFilter, HTTPFilterPriority)] = [],
		                          responseFilters: [(HTTPResponseFilter, HTTPFilterPriority)] = []) -> Server {
			return HTTPServer.Server(name: name, port: port, routes: routes, requestFilters: requestFilters, responseFilters: responseFilters)
		}

		public static func server(name: String, port: Int, routes: [Route],
		                          requestFilters: [(HTTPRequestFilter, HTTPFilterPriority)] = [],
		                          responseFilters: [(HTTPResponseFilter, HTTPFilterPriority)] = []) -> Server {
			return HTTPServer.Server(name: name, port: port, routes: Routes(routes), requestFilters: requestFilters, responseFilters: responseFilters)
		}

		public static func server(name: String, port: Int, documentRoot root: String,
		                          requestFilters: [(HTTPRequestFilter, HTTPFilterPriority)] = [],
		                          responseFilters: [(HTTPResponseFilter, HTTPFilterPriority)] = []) -> Server {
			let sfh = StaticFileHandler(documentRoot: root, allowResponseFilters: 0 < (requestFilters.count + responseFilters.count))
			let routes = Routes([
				.init(method: .get, uri: "/**", handler: sfh.handleRequest),
				.init(method: .head, uri: "/**", handler: sfh.handleRequest)
				])
			return HTTPServer.Server(name: name, port: port, routes: routes, requestFilters: requestFilters, responseFilters: responseFilters)
		}

		public static func secureServer(_ tlsConfig: TLSConfiguration, name: String, port: Int, routes: [Route],
		                                requestFilters: [(HTTPRequestFilter, HTTPFilterPriority)] = [],
		                                responseFilters: [(HTTPResponseFilter, HTTPFilterPriority)] = []) -> Server {
			return HTTPServer.Server(tlsConfig: tlsConfig, name: name, port: port, routes: Routes(routes), requestFilters: requestFilters, responseFilters: responseFilters)
		}

		public static func secureServer(_ tlsConfig: TLSConfiguration, name: String, port: Int, routes: Routes,
		                                requestFilters: [(HTTPRequestFilter, HTTPFilterPriority)] = [],
		                                responseFilters: [(HTTPResponseFilter, HTTPFilterPriority)] = []) -> Server {
			return HTTPServer.Server(tlsConfig: tlsConfig, name: name, port: port, routes: routes, requestFilters: requestFilters, responseFilters: responseFilters)
		}
	}
}

protocol ServerInstance {
	func start() throws
	func bind() throws
	func stop()
}

public extension HTTPServer {
	struct LaunchFailure: Error {
		let message: String
		let configuration: Server
	}

	class LaunchContext {
		private let event = Threading.Event()
		var error: Error?
		public var terminated = false
		public let server: Server
		var httpServer: ServerInstance?

		var id: String { return "\(server.name):\(server.port)" }

		init(_ server: Server) {
			self.server = server
		}

		init(_ server: HTTPMultiplexer) {
			self.httpServer = server
			self.server = server.synthServer
		}

		@discardableResult
		public func terminate() -> LaunchContext {
			if !terminated, let httpServer = self.httpServer {
				httpServer.stop()
			}
			return self
		}

		// if the ctx indicated an error then we translate it into a throw
		@discardableResult
		public func wait(seconds: Double = Threading.noTimeout) throws -> Bool {
			event.lock()
			defer {
				event.unlock()
			}
			if !terminated {
				_ = event.wait(seconds: seconds)
			}
			if terminated, let error = self.error {
				switch error {
				case PerfectNetError.networkError(let code, let msg):
					switch code {
					case 53:
						() // socket was closed. not an error
					case 48:
						throw LaunchFailure(message: "Server \(id) - Another server was already listening on the requested port \(server.port)", configuration: server)
					default:
						throw LaunchFailure(message: "Server \(id) - \(code):\(msg)", configuration: server)
					}
				default:
					throw LaunchFailure(message: "Server \(id) - \(error)", configuration: server)
				}
			}
			return terminated
		}

		func bindServer() throws {
			if nil == httpServer {
				httpServer = server.server
			}
			guard let httpServer = self.httpServer else {
				throw LaunchFailure(message: "Could not get HTTPServer", configuration: server)
			}
			do {
				try httpServer.bind()
			} catch PerfectNetError.networkError(let code, let msg) {
				switch code {
				case 48:
					throw LaunchFailure(message: "Server \(id) - Another server was already listening on the requested port \(server.port)", configuration: server)
				default:
					throw LaunchFailure(message: "Server \(id) - \(code):\(msg)", configuration: server)
				}
			} catch {
				throw LaunchFailure(message: "Server \(id) - \(error)", configuration: server)
			}
		}

		@discardableResult
		func launchServer() throws -> LaunchContext {
			guard let httpServer = self.httpServer else {
				throw LaunchFailure(message: "Could not get HTTPServer", configuration: server)
			}
			let q = Threading.getQueue(name: "Server \(id) \(Foundation.UUID().uuidString)", type: .serial)
			q.dispatch {
				do {
					try httpServer.start()
				} catch {
					self.error = error
				}
				self.event.lock()
				defer {
					self.event.unlock()
				}
				self.terminated = true
				self.event.signal()
			}
			return self
		}
	}
}

public extension HTTPServer {

	@discardableResult
	static func launch(wait: Bool = true, _ server: Server, _ servers: Server...) throws -> [LaunchContext] {
		return try launch(wait: wait, [server] + servers)
	}

	@discardableResult
	static func launch(wait: Bool = true, name: String, port: Int, routes: [Route], requestFilters: [(HTTPRequestFilter, HTTPFilterPriority)] = [], responseFilters: [(HTTPResponseFilter, HTTPFilterPriority)] = []) throws -> LaunchContext {
		return try launch(wait: wait, name: name, port: port, routes: Routes(routes), requestFilters: requestFilters, responseFilters: responseFilters)
	}

	static func getLaunchContexts(_ servers: [Server]) throws -> [LaunchContext] {
		var notSSL = [Server]()
		var singleServers = [String: Server]()
		var multiplexers = [String: HTTPMultiplexer]()
		for server in servers {
			if nil != server.tlsConfig {
				let id = "\(server.address):\(server.port)"
				if let existingMulti = multiplexers[id] {
					try existingMulti.addServer(server.server)
				} else if let existingSingle = singleServers[id] {
					singleServers.removeValue(forKey: id)
					let multi = HTTPMultiplexer()
					try multi.addServer(existingSingle.server)
					try multi.addServer(server.server)
					multiplexers[id] = multi
				} else {
					singleServers[id] = server
				}
			} else {
				notSSL.append(server)
			}
		}
		return (notSSL + singleServers.values).map { LaunchContext($0) } + multiplexers.values.map { LaunchContext($0) }
	}

	// launch with array
	@discardableResult
	static func launch(wait: Bool = true, _ servers: [Server]) throws -> [LaunchContext] {
		let ctx = try getLaunchContexts(servers)
		try ctx.forEach { try $0.bindServer() }
		try switchUser()
		try ctx.forEach { try $0.launchServer() }
		try ctx.forEach { try $0.wait(seconds: 1.0) }
		if wait {
			try ctx.forEach {
				repeat {
					()
				} while try $0.wait() == false
			}
		}
		return ctx
	}

	// launch one
	@discardableResult
	static func launch(wait: Bool = true, name: String, port: Int, routes: Routes, requestFilters: [(HTTPRequestFilter, HTTPFilterPriority)] = [], responseFilters: [(HTTPResponseFilter, HTTPFilterPriority)] = []) throws -> LaunchContext {
		return try launch(wait: wait, [.server(name: name, port: port, routes: routes, requestFilters: requestFilters, responseFilters: responseFilters)])[0]
	}

	// launch one with document root
	@discardableResult
	static func launch(wait: Bool = true, name: String, port: Int, documentRoot root: String, requestFilters: [(HTTPRequestFilter, HTTPFilterPriority)] = [], responseFilters: [(HTTPResponseFilter, HTTPFilterPriority)] = []) throws -> LaunchContext {
		return try launch(wait: wait, [.server(name: name, port: port, documentRoot: root, requestFilters: requestFilters, responseFilters: responseFilters)])[0]
	}

	private static func switchUser() throws {
		guard let runAs = processRunAs else {
			return
		}
		try PerfectServer.switchTo(userName: runAs)
	}
}

private extension HTTPServer.Server {
	init(data: [String: Any]) throws {
		guard let name = data["name"] as? String else {
			throw PerfectError.apiError("Server data did not contain a name")
		}
		guard let port = data["port"] as? Int else {
			throw PerfectError.apiError("Server data did not contain an integer port")
		}
		self.name = name
		self.port = port
		self.address = data["address"] as? String ?? "0.0.0.0"
		self.routes = try Routes(data: data["routes"] as? [[String: Any]] ?? [])

		let filters = data["filters"] as? [[String: Any]] ?? []
		self.requestFilters = try filtersFrom(data: filters)
		self.responseFilters = try filtersFrom(data: filters)

		self.tlsConfig = TLSConfiguration(data: data["tlsConfig"] as? [String: Any] ?? [:])
	}
}

public extension HTTPServer {
	@discardableResult
	static func launch(wait: Bool = true, configurationPath path: String) throws -> [LaunchContext] {
		return try launch(wait: wait, configurationFile: File(path))
	}
	@discardableResult
	static func launch(wait: Bool = true, configurationFile file: File) throws -> [LaunchContext] {
		let string = try file.readString()
		guard let jsonData = try string.jsonDecode() as? [String: Any] else {
			throw PerfectError.apiError("Data in \(file.path) could not convert to [String:Any]")
		}
		return try launch(wait: wait, configurationData: jsonData)
	}
	@discardableResult
	static func launch(wait: Bool = true, configurationData data: [String: Any]) throws -> [LaunchContext] {
		processRunAs = data["runAs"] as? String
		guard let servers = data["servers"] as? [[String: Any]] else {
			return []
		}
		let serversObjs = try servers.map { try HTTPServer.Server(data: $0) }
		return try launch(wait: wait, serversObjs)
	}
}
