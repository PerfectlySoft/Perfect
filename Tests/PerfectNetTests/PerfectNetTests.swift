import XCTest
@testable import PerfectNet
import PerfectThread

#if os(Linux)
	import SwiftGlibc
#endif

let localhost = "127.0.0.1"

class PerfectNetTests: XCTestCase {

    override func setUp() {
        super.setUp()
    }

    func testClientServer() {
        let port = UInt16(6501)
        do {
			let b: [UInt8] = [1, 2, 3, 4, 5]
            let server = NetTCP()
			var serverAccept: NetTCP?
            let client = NetTCP()
            try server.bind(port: port, address: localhost)
            server.listen()
            let serverExpectation = self.expectation(description: "server")
            let clientExpectation = self.expectation(description: "client")
            try server.accept(timeoutSeconds: NetEvent.noTimeout) { inn in
				serverAccept = inn
                guard let n = inn else {
                    XCTAssertNotNil(inn)
                    return
                }
				n.write(bytes: b) { sent in
					XCTAssertTrue(sent == b.count)
					n.readBytesFully(count: b.count, timeoutSeconds: 5.0) { read in
						XCTAssert(read != nil)
						XCTAssert(read?.count == b.count)
						if nil != serverAccept {
							serverAccept = nil
						}
						serverExpectation.fulfill()
					}
				}
            }

			Threading.sleep(seconds: 1.0)
            try client.connect(address: localhost, port: port, timeoutSeconds: 5) { (inn: NetTCP?) -> () in
                guard let n = inn else {
                    XCTAssertNotNil(inn)
                    return
                }
				n.readBytesFully(count: b.count, timeoutSeconds: 5.0) { read in
					XCTAssert(read != nil)
					XCTAssert(read!.count == b.count)
					n.write(bytes: b) { sent in
						XCTAssertTrue(sent == b.count)
						Threading.sleep(seconds: 1.0)
						n.shutdown()
						clientExpectation.fulfill()
					}
				}
            }
			self.waitForExpectations(timeout: 10) { _ in
				server.close()
				client.close()
			}
        } catch PerfectNetError.networkError(let code, let msg) {
            XCTFail("Exception: \(code) \(msg)")
        } catch let e {
            XCTFail("Exception: \(e)")
        }
    }

    func testClientServerReadTimeout() {
        let port = UInt16(6500)
        do {
            let server = NetTCP()
            let client = NetTCP()
            try server.bind(port: port, address: localhost)
            server.listen()
            let serverExpectation = self.expectation(description: "server")
            let clientExpectation = self.expectation(description: "client")
            try server.accept(timeoutSeconds: NetEvent.noTimeout) { (inn: NetTCP?) -> () in
                guard nil != inn else {
                    XCTAssertNotNil(inn)
                    return
                }
                Threading.sleep(seconds: 5)
                serverExpectation.fulfill()
            }
			var once = false
			Threading.sleep(seconds: 1.0)
            try client.connect(address: localhost, port: port, timeoutSeconds: 5) { (inn: NetTCP?) -> () in
                guard let n = inn else {
                    XCTAssertNotNil(inn)
                    return
                }
                do {
                    n.readBytesFully(count: 1, timeoutSeconds: 2.0) { read in
                        XCTAssert(read?.isEmpty ?? false)
                        XCTAssert(once == false)
                        once = !once
                        Threading.sleep(seconds: 7)
                        XCTAssert(once == true)
                        clientExpectation.fulfill()
                    }
                }
            }
			self.waitForExpectations(timeout: 10000, handler: { _ in
				server.close()
				client.close()
			})
        } catch PerfectNetError.networkError(let code, let msg) {
            XCTFail("Exception: \(code) \(msg)")
        } catch let e {
            XCTFail("Exception: \(e)")
        }
    }

    func testTCPSSLClient() {
        let address = "www.treefrog.ca"
        let requestString = [UInt8](("GET / HTTP/1.0\r\nHost: \(address)\r\n\r\n").utf8)
        let requestCount = requestString.count
		let clientExpectation = self.expectation(description: "client")
        let net = NetTCPSSL()
        do {
			try net.connect(address: address, port: 443, timeoutSeconds: 5.0) { net in
                if let ssl = net as? NetTCPSSL {
					do {
						let x509 = ssl.peerCertificate
						XCTAssert(x509 != nil)
						let peerKey = x509?.publicKeyBytes
						XCTAssert(peerKey != nil && peerKey!.count > 0)
					}

					ssl.write(bytes: requestString) { sent in
						XCTAssert(sent == requestCount)
						ssl.readBytesFully(count: 1, timeoutSeconds: 5.0) { readBytes in
							XCTAssert(readBytes != nil && readBytes!.count > 0)
							var readBytesCpy = readBytes!
							readBytesCpy.append(0)
							let s1 = readBytesCpy.withUnsafeBytes { String(validatingUTF8: $0.bindMemory(to: CChar.self).baseAddress!)! }
							ssl.readSomeBytes(count: 4096) { readBytes in
								XCTAssert(readBytes != nil && readBytes!.count > 0)
								var readBytesCpy = readBytes!
								readBytesCpy.append(0)
								let s2 = readBytesCpy.withUnsafeBytes { String(validatingUTF8: $0.bindMemory(to: CChar.self).baseAddress!)! }
								let s = s1 + s2
								XCTAssert(s.starts(with: "HTTP/1.1 200 OK"))
								clientExpectation.fulfill()
							}
						}
                    }
                } else {
                    XCTFail("Did not get NetTCPSSL back after connect")
                }
            }
        } catch {
            XCTFail("Exception thrown")
        }
		self.waitForExpectations(timeout: 10000) { _ in
			net.close()
		}
    }

	func testMakeAddress() {
		do {
			let r = NetAddress(host: "localhost", port: 80)
			XCTAssert(r != nil)
			XCTAssert(r?.addr.ss_family == sa_family_t(AF_INET6) || r?.addr.ss_family == sa_family_t(AF_INET))
		}
		do {
			let r = NetAddress(host: "127.0.0.1", port: 80)
			XCTAssert(r != nil)
			XCTAssert(r?.addr.ss_family == sa_family_t(AF_INET))
		}
		do {
			let r = NetAddress(host: "0.0.0.0", port: 80)
			XCTAssert(r != nil)
			XCTAssert(r?.addr.ss_family == sa_family_t(AF_INET))
		}

		do {
			let r = NetAddress(host: "www.google.com", port: 80)
			XCTAssert(r != nil)
			XCTAssert(r?.addr.ss_family == sa_family_t(AF_INET6) || r?.addr.ss_family == sa_family_t(AF_INET))
		}

		do {
			let r = NetAddress(host: "www.perfect.org", port: 80)
			XCTAssert(r != nil)
			XCTAssert(r?.addr.ss_family == sa_family_t(AF_INET6) || r?.addr.ss_family == sa_family_t(AF_INET))
		}

		do {
			let r = NetAddress(host: "::", port: 80)
			XCTAssert(r != nil)
			XCTAssert(r?.addr.ss_family == sa_family_t(AF_INET6))
		}
	}

	func testUDPClientServer() {
		let listenPort = UInt16(8979)
		let client = NetUDP()
		let server = NetUDP()
		let clientExpectation = self.expectation(description: "client")
		let serverExpectation = self.expectation(description: "server")

		Threading.dispatch {
			do {
				try server.bind(port: listenPort, address: "127.0.0.1")
				server.listen()
				let loops = 2048
				Threading.dispatch {
					func loop(counter: Int) {
						guard counter != loops else {
							return serverExpectation.fulfill()
						}
						server.readBytes(count: counter+1, timeoutSeconds: 60.0) { f in
							do {
								guard let (bytes, _) = try f() else {
									XCTFail("Nil response \(counter)")
									return serverExpectation.fulfill()
								}
								XCTAssert(bytes.count == counter+1)
//								print("read \(bytes.count)")
								Threading.dispatch {
									loop(counter: counter+1)
								}
							} catch {
								XCTFail("\(error)")
								return serverExpectation.fulfill()
							}
						}
					}
					loop(counter: 0)
				}
				Threading.sleep(seconds: 1.0)
				Threading.dispatch {
					guard let address = NetAddress(host: "127.0.0.1", port: listenPort, type: .udp) else {
						XCTFail("Could not make address")
						return clientExpectation.fulfill()
					}
					func loop(counter: Int) {
						guard counter != loops else {
							return clientExpectation.fulfill()
						}
						let bytesToWrite = [UInt8](repeating: 1, count: counter+1)
						client.write(bytes: bytesToWrite, to: address, timeoutSeconds: 60.0) { f in
							do {
								let (wrote, _) = try f()
								XCTAssert(wrote == counter+1)
								Threading.dispatch {
									Threading.sleep(seconds: 0.01)
									loop(counter: counter+1)
								}
							} catch {
								XCTFail("\(error)")
								return clientExpectation.fulfill()
							}
						}
					}
					loop(counter: 0)
				}
			} catch {
				XCTFail("\(error)")
				clientExpectation.fulfill()
				serverExpectation.fulfill()
			}
		}

		self.waitForExpectations(timeout: 10000) { _ in
			client.close()
			server.close()
		}
	}
}
