//
//  HTTPMultiplexer.swift
//  HTTP2Test
//
//  Created by Kyle Jessup on 2017-06-29.
//
//

import PerfectNet
import PerfectLib
#if os(Linux)
	import SwiftGlibc
	import LinuxBridge
#else
	import Darwin
#endif

class HTTPMultiplexer: ServerInstance {
	var synthServer = HTTPServer.Server()
	var servers: [String: HTTPServer] = [:]
	var port: UInt16 = 0
	var address: String = ""
	var net: NetTCPSSL?

	func addServer(_ server: HTTPServer) throws {
		let name = server.serverName.lowercased()
		if nil != servers[name] {
			throw HTTPServer.LaunchFailure(message: "Server name \"\(name)\" already exists. Each server listening on the same port must have a unique server name.", configuration: synthServer)
		}
		guard nil != server.ssl else {
			throw HTTPServer.LaunchFailure(message: "Server name \"\(name)\" must be a secure server.", configuration: synthServer)
		}
		if servers.count == 0 {
			// first server
			port = server.serverPort
			address = server.serverAddress
			synthServer = .init(name: "HTTPMultiplexer - \(address):\(port)",
				address: address,
				port: Int(port),
				routes: .init())
		} else {
			guard server.serverPort == port && server.serverAddress == address else {
				throw HTTPServer.LaunchFailure(message: "Server name \"\(name)\" does not have same address or port as rest of group. Want \(address):\(port) got \(server.serverAddress):\(server.serverPort)", configuration: synthServer)
			}
		}
		servers[name] = server
	}

	func start() throws {
		guard let net = self.net else {
			throw HTTPServer.LaunchFailure(message: "Server not bound.", configuration: synthServer)
		}
		for (name, server) in servers {
			guard let (cert, key) = server.ssl else {
				throw HTTPServer.LaunchFailure(message: "Server name \"\(name)\" must have certificate file.", configuration: synthServer)
			}
			if let verifyMode = server.certVerifyMode,
				let cert = server.caCert,
				verifyMode != .sslVerifyNone {

				guard net.setClientCA(path: cert, verifyMode: verifyMode, forHost: name) else {
					let code = Int32(net.errorCode())
					throw HTTPServer.LaunchFailure(message: "Error setting clientCA: \(cert) \(net.errorStr(forCode: code))", configuration: synthServer)
				}
			}
			guard net.useCertificateChainFile(cert: cert, forHost: name) else {
				let code = Int32(net.errorCode())
				throw HTTPServer.LaunchFailure(message: "Error setting certificate chain file: \(cert) \(net.errorStr(forCode: code))", configuration: synthServer)
			}
			guard net.usePrivateKeyFile(cert: key, forHost: name) else {
				let code = Int32(net.errorCode())
				throw HTTPServer.LaunchFailure(message: "Error setting private key file: \(key) \(net.errorStr(forCode: code))", configuration: synthServer)
			}
			guard net.checkPrivateKey(forHost: name) else {
				let code = Int32(net.errorCode())
				throw HTTPServer.LaunchFailure(message: "Error validating private key file: \(net.errorStr(forCode: code))", configuration: synthServer)
			}
			net.enableALPN(protocols: server.alpnSupport.map { $0.rawValue }, forHost: name)
		}
		net.listen()
		var flag = 1
		_ = setsockopt(net.fd.fd, Int32(IPPROTO_TCP), TCP_NODELAY, &flag, UInt32(MemoryLayout<Int32>.size))

		defer { net.close() }

		Log.info(message: "Starting multi-server for \(servers.count) hosts on \(self.address):\(self.port)")

		net.forEachAccept { net in
			guard let net = net as? NetTCPSSL else {
				return
			}
			let sn = net.serverNameIdentified
			if nil != sn, let server = self.servers[sn!.lowercased()] {
				server.accepted(net: net)
			} else if let server = self.servers["*"] {
				server.accepted(net: net)
			} else {
				net.close()
				Log.warning(message: "Client wanted host \(sn ?? "*"). Server not found.")
			}
		}
	}

	func bind() throws {
		guard nil == self.net else {
			throw HTTPServer.LaunchFailure(message: "Server already bound.", configuration: synthServer)
		}
		guard !servers.isEmpty else {
			throw HTTPServer.LaunchFailure(message: "No servers have been added.", configuration: synthServer)
		}

		let net = NetTCPSSL()
		try net.bind(port: port, address: address)
		self.net = net
	}

	func stop() {
		net?.shutdown()
	}
}
