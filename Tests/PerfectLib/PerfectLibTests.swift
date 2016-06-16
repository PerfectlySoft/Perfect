//
//  PerfectLibTests.swift
//  PerfectLibTests
//
//  Created by Kyle Jessup on 2015-10-19.
//  Copyright © 2015 PerfectlySoft. All rights reserved.
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


import XCTest
import PerfectNet
import PerfectThread
@testable import PerfectLib

#if os(Linux)
import SwiftGlibc
#endif

class PerfectLibTests: XCTestCase {

	override func setUp() {
		super.setUp()
	#if os(Linux)
		SwiftGlibc.srand(UInt32(time(nil)))
	#endif
		// Put setup code here. This method is called before the invocation of each test method in the class.
		NetEvent.initialize()
	}

	override func tearDown() {
		// Put teardown code here. This method is called after the invocation of each test method in the class.
		super.tearDown()
	}

	func _rand(to upper: Int32) -> Int32 {
    #if os(OSX)
		return Int32(arc4random_uniform(UInt32(upper)))
	#else
		return SwiftGlibc.rand() % Int32(upper)
	#endif
	}

	func testConcurrentQueue() {
		let q = Threading.getQueue(name: "concurrent", type: .concurrent)

		var t1 = 0, t2 = 0, t3 = 0

		q.dispatch {
			t1 = 1
			Threading.sleep(seconds: 5)
		}
		q.dispatch {
			t2 = 1
			Threading.sleep(seconds: 5)
		}
		q.dispatch {
			t3 = 1
			Threading.sleep(seconds: 5)
		}
		Threading.sleep(seconds: 1)

		XCTAssert(t1 == 1 && t2 == 1 && t3 == 1)
	}

	func testSerialQueue() {
		let q = Threading.getQueue(name: "serial", type: .serial)

		var t1 = 0

		q.dispatch {
			XCTAssert(t1 == 0)
			t1 = 1
		}
		q.dispatch {
			XCTAssert(t1 == 1)
			t1 = 2
		}
		q.dispatch {
			XCTAssert(t1 == 2)
			t1 = 3
		}
		Threading.sleep(seconds: 2)
		XCTAssert(t1 == 3)
	}

	func testJSONConvertibleObject() {

		class Test: JSONConvertibleObject {

			static let registerName = "test"

			var one = 0
			override func setJSONValues(_ values: [String : Any]) {
				self.one = getJSONValue(named: "One", from: values, defaultValue: 42)
			}
			override func getJSONValues() -> [String : Any] {
				return [JSONDecoding.objectIdentifierKey:Test.registerName, "One":1]
			}
		}

		JSONDecoding.registerJSONDecodable(name: Test.registerName, creator: { return Test() })

		do {
			let encoded = try Test().jsonEncodedString()
			let decoded = try encoded.jsonDecode() as? Test

			XCTAssert(decoded != nil)

			XCTAssert(decoded!.one == 1)
		} catch {
			XCTAssert(false, "Exception \(error)")
		}
	}

	func testJSONEncodeDecode() {

		let srcAry: [[String:Any]] = [["i": -41451, "i2": 41451, "d": -42E+2, "t": true, "f": false, "n": nil as String?, "a":[1, 2, 3, 4]], ["another":"one"]]
		var encoded = ""
		var decoded: [Any]?
		do {

			encoded = try srcAry.jsonEncodedString()

		} catch let e {
			XCTAssert(false, "Exception while encoding JSON \(e)")
			return
		}

		do {

			decoded = try encoded.jsonDecode() as? [Any]

		} catch let e {
			XCTAssert(false, "Exception while decoding JSON \(e)")
			return
		}

		XCTAssert(decoded != nil)

		let resAry = decoded!

		XCTAssert(srcAry.count == resAry.count)

		for index in 0..<srcAry.count {

			let d1 = srcAry[index]
			let d2 = resAry[index] as? [String:Any]

			for (key, value) in d1 {

				let value2 = d2![key]

				XCTAssert(value2 != nil)

				switch value {
				case let i as Int:
					XCTAssert(i == value2 as! Int)
				case let d as Double:
					XCTAssert(d == value2 as! Double)
				case let s as String:
					XCTAssert(s == value2 as! String)
				case let s as Bool:
					XCTAssert(s == value2 as! Bool)

				default:
					()
					// does not go on to test sub-sub-elements
				}
			}

		}
	}

	func testJSONDecodeUnicode() {
		var decoded: [String: Any]?
		let jsonStr = "{\"emoji\": \"\\ud83d\\ude33\"}"     // {"emoji": "\ud83d\ude33"}
		do {
			decoded = try jsonStr.jsonDecode() as? [String: Any]
		} catch let e {

			XCTAssert(false, "Exception while decoding JSON \(e)")
			return
		}

		XCTAssert(decoded != nil)
		let value = decoded!["emoji"]
		XCTAssert(value != nil)
		let emojiStr = decoded!["emoji"] as! String
		XCTAssert(emojiStr == "😳")
	}

	func testMimeReaderSimple() {

		let boundary = "--6"

		var testData = Array<Dictionary<String, String>>()
		let numTestFields = 2

		for idx in 0..<numTestFields {
			var testDic = Dictionary<String, String>()

			testDic["name"] = "test_field_\(idx)"

			var testValue = ""
			for _ in 1...4 {
				testValue.append("O")
			}
			testDic["value"] = testValue

			testData.append(testDic)
		}

		let file = File("/tmp/mimeReaderTest.txt")
		do {

			try file.open(.truncate)

			for testDic in testData {
				let _ = try file.write(string: "--" + boundary + "\r\n")

				let testName = testDic["name"]!
				let testValue = testDic["value"]!

				let _ = try file.write(string: "Content-Disposition: form-data; name=\"\(testName)\"; filename=\"\(testName).txt\"\r\n")
				let _ = try file.write(string: "Content-Type: text/plain\r\n\r\n")
				let _ = try file.write(string: testValue)
				let _ = try file.write(string: "\r\n")
			}

			let _ = try file.write(string: "--" + boundary + "--")

			for num in 1...1 {

				file.close()
				try file.open()

				let mimeReader = MimeReader("multipart/form-data; boundary=" + boundary)

				XCTAssertEqual(mimeReader.boundary, "--" + boundary)

				var bytes = try file.readSomeBytes(count: num)
				while bytes.count > 0 {
					mimeReader.addToBuffer(bytes: bytes)
					bytes = try file.readSomeBytes(count: num)
				}

				XCTAssertEqual(mimeReader.bodySpecs.count, testData.count)

				var idx = 0
				for body in mimeReader.bodySpecs {

					let testDic = testData[idx]
					idx += 1
					XCTAssertEqual(testDic["name"]!, body.fieldName)

					let file = File(body.tmpFileName)
					try file.open()
					let contents = try file.readSomeBytes(count: file.size)
					file.close()

					let decoded = UTF8Encoding.encode(bytes: contents)
					let v = testDic["value"]!
					XCTAssertEqual(v, decoded)

					body.cleanup()
				}
			}

			file.close()
			file.delete()

		} catch let e {
			print("Exception while testing MimeReader: \(e)")
		}
	}

	func testNetSendFile() {

		let testFile = File("/tmp/file_to_send.txt")
		let testContents = "Here are the contents"
		let sock = "/tmp/foo.sock"
		let sockFile = File(sock)
		if sockFile.exists {
			sockFile.delete()
		}

		do {

			try testFile.open(.truncate)
			let _ = try testFile.write(string: testContents)
			testFile.close()
			try testFile.open()

			let server = NetNamedPipe()
			let client = NetNamedPipe()

			try server.bind(address: sock)
			server.listen()

		#if swift(>=3.0)
			let serverExpectation = self.expectation(withDescription: "server")
			let clientExpectation = self.expectation(withDescription: "client")
		#else
			let serverExpectation = self.expectationWithDescription("server")
			let clientExpectation = self.expectationWithDescription("client")
		#endif

			try server.accept(timeoutSeconds: NetEvent.noTimeout) {
				(inn: NetTCP?) -> () in
				let n = inn as? NetNamedPipe
				XCTAssertNotNil(n)

				do {
					try n?.sendFile(testFile) {
						(b: Bool) in

						XCTAssertTrue(b)

						n!.close()

						serverExpectation.fulfill()
					}
				} catch let e {
					XCTAssert(false, "Exception accepting connection: \(e)")
					serverExpectation.fulfill()
				}
			}

			try client.connect(address: sock, timeoutSeconds: 5) {
				(inn: NetTCP?) -> () in
				let n = inn as? NetNamedPipe
				XCTAssertNotNil(n)

				do {
					try n!.receiveFile {
						(f: File?) in

						XCTAssertNotNil(f)

						do {
							let testDataRead = try f!.readSomeBytes(count: f!.size)
							if testDataRead.count > 0 {
								XCTAssertEqual(UTF8Encoding.encode(bytes: testDataRead), testContents)
							} else {
								XCTAssertTrue(false, "Got no data from received file")
							}

							f!.close()
						} catch let e {
							XCTAssert(false, "Exception in connection: \(e)")
						}
						clientExpectation.fulfill()
					}

				} catch let e {
					XCTAssert(false, "Exception in connection: \(e)")
					clientExpectation.fulfill()
				}
			}

		#if swift(>=3.0)
			self.waitForExpectations(withTimeout: 10000, handler: {
				_ in
				server.close()
				client.close()
				testFile.close()
				testFile.delete()
			})
		#else
			self.waitForExpectationsWithTimeout(10000, handler: {
				_ in
				server.close()
				client.close()
				testFile.close()
				testFile.delete()
			})
		#endif

		} catch PerfectError.networkError(let code, let msg) {
			XCTAssert(false, "Exception: \(code) \(msg)")
		} catch let e {
			XCTAssert(false, "Exception: \(e)")
		}
	}

	func testSysProcess() {

		do {
			let proc = try SysProcess("ls", args:["-l", "/"], env:[("PATH", "/usr/bin:/bin")])

			XCTAssertTrue(proc.isOpen())
			XCTAssertNotNil(proc.stdin)

			let fileOut = proc.stdout!
			let data = try fileOut.readSomeBytes(count: 4096)

			XCTAssertTrue(data.count > 0)

			let waitRes = try proc.wait()

			XCTAssert(0 == waitRes, "\(waitRes) \(UTF8Encoding.encode(bytes: data))")

			proc.close()
		} catch let e {
			print("\(e)")
			XCTAssert(false, "Exception running SysProcess test")
		}
	}

	func testStringByEncodingHTML() {
		let src = "<b>\"quoted\" '& ☃"
		let res = src.stringByEncodingHTML
		XCTAssertEqual(res, "&lt;b&gt;&quot;quoted&quot; &#39;&amp; &#9731;")
	}

	func testStringByEncodingURL() {
		let src = "This has \"weird\" characters & ßtuff"
		let res = src.stringByEncodingURL
		XCTAssertEqual(res, "This%20has%20%22weird%22%20characters%20&%20%C3%9Ftuff")
	}

	func testStringByDecodingURL() {
		let src = "This has \"weird\" characters & ßtuff"
		let mid = src.stringByEncodingURL
		guard let res = mid.stringByDecodingURL else {
			XCTAssert(false, "Got nil String")
			return
		}
		XCTAssert(res == src, "Bad URL decoding")
	}

	func testStringByDecodingURL2() {
		let src = "This is badly%PWencoded"
		let res = src.stringByDecodingURL

		XCTAssert(res == nil, "Bad URL decoding")
	}

	func testStringByReplacingString() {

		let src = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ"
		let test = "ABCFEDGHIJKLMNOPQRSTUVWXYZABCFEDGHIJKLMNOPQRSTUVWXYZABCFEDGHIJKLMNOPQRSTUVWXYZ"
		let find = "DEF"
		let rep = "FED"

		let res = src.stringByReplacing(string: find, withString: rep)

		XCTAssert(res == test)
	}

	func testStringByReplacingString2() {

		let src = ""
		let find = "DEF"
		let rep = "FED"

		let res = src.stringByReplacing(string: find, withString: rep)

		XCTAssert(res == src)
	}

	func testStringByReplacingString3() {

		let src = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ"
		let find = ""
		let rep = "FED"

		let res = src.stringByReplacing(string: find, withString: rep)

		XCTAssert(res == src)
	}

	func testSubstringTo() {

		let src = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ"
		let res = src.substring(to: src.index(src.startIndex, offsetBy: 5))

		XCTAssert(res == "ABCDE")
	}

	func testRangeTo() {

		let src = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

		let res = src.range(ofString: "DEF")
		XCTAssert(res == src.index(src.startIndex, offsetBy: 3)..<src.index(src.startIndex, offsetBy: 6))

		let res2 = src.range(ofString: "FED")
		XCTAssert(res2 == nil)


		let res3 = src.range(ofString: "def", ignoreCase: true)
		XCTAssert(res3 == src.index(src.startIndex, offsetBy: 3)..<src.index(src.startIndex, offsetBy: 6))
	}

	func testSubstringWith() {

		let src = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		let range = src.index(src.startIndex, offsetBy: 3)..<src.index(src.startIndex, offsetBy: 6)
		XCTAssert("DEF" == src.substring(with: range))
	}

	func testICUFormatDate() {
		let dateThen = 0.0
		let formatStr = "%a, %d-%b-%Y %T GMT"
		do {
			let result = try formatDate(dateThen, format: formatStr, timezone: "GMT")
			XCTAssertEqual(result, "Thu, 01-Jan-1970 00:00:00 GMT")
		} catch let e {
			print("\(e)")
			XCTAssert(false, "Exception running testICUFormatDate")
		}
	}

	func testMustacheParser1() {
		let usingTemplate = "TOP {\n{{#name}}\n{{name}}{{/name}}\n}\nBOTTOM"
		do {
			let template = try MustacheParser().parse(string: usingTemplate)
			let d = ["name":"The name"] as [String:Any]

            let connection = HTTPServer.HTTPWebConnection()
            let response = WebResponse(connection, request: WebRequest(connection))

            let context = MustacheEvaluationContext(webResponse: response, map: d)
			let collector = MustacheEvaluationOutputCollector()
			template.evaluate(context: context, collector: collector)

			XCTAssertEqual(collector.asString(), "TOP {\n\nThe name\n}\nBOTTOM")
		} catch {
			XCTAssert(false)
		}
	}

	func testStringBeginsWith() {
		let a = "123456"

		XCTAssert(a.begins(with: "123"))
		XCTAssert(!a.begins(with: "abc"))
	}

	func testStringEndsWith() {
		let a = "123456"

		XCTAssert(a.ends(with: "456"))
		XCTAssert(!a.ends(with: "abc"))
	}

	func testHPACKEncode() {

		let encoder = HPACKEncoder(maxCapacity: 256)
		let b = Bytes()

		let headers = [
			(":method", "POST"),
			(":scheme", "https"),
			(":path", "/3/device/00fc13adff785122b4ad28809a3420982341241421348097878e577c991de8f0"),
			("host", "api.development.push.apple.com"),
			("apns-id", "eabeae54-14a8-11e5-b60b-1697f925ec7b"),
			("apns-expiration", "0"),
			("apns-priority", "10"),
			("content-length", "33")]
		do {
			for (n, v) in headers {
				try encoder.encodeHeader(out: b, name: UTF8Encoding.decode(string: n), value: UTF8Encoding.decode(string: v), sensitive: false)
			}

			class Listener: HeaderListener {
				var headers = [(String, String)]()
				func addHeader(name nam: [UInt8], value: [UInt8], sensitive: Bool) {
					self.headers.append((UTF8Encoding.encode(bytes: nam), UTF8Encoding.encode(bytes: value)))
				}
			}

			let decoder = HPACKDecoder(maxHeaderSize: 256, maxHeaderTableSize: 256)
			let l = Listener()
			try decoder.decode(input: b, headerListener: l)

			XCTAssert(l.headers.count == headers.count)

			for i in 0..<headers.count {
				let h1 = headers[i]
				let h2 = l.headers[i]

				XCTAssert(h1.0 == h2.0)
				XCTAssert(h1.1 == h2.1)
			}

		}
		catch {
			XCTAssert(false, "Exception \(error)")
		}
	}

	func testWebConnectionHeadersWellFormed() {
		let connection = HTTPServer.HTTPWebConnection()

		let fullHeaders = "GET / HTTP/1.1\r\nX-Foo: bar\r\nX-Bar: \r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n"

		connection.workingBuffer = UTF8Encoding.decode(string: fullHeaders)

		connection.scanWorkingBuffer {
			ok in

			XCTAssertTrue(ok)
			XCTAssertTrue(connection.requestParams["HTTP_X_FOO"] == "bar", "\(connection.requestParams)")
			XCTAssertTrue(connection.requestParams["HTTP_X_BAR"] == "", "\(connection.requestParams)")
			XCTAssertTrue(connection.contentType == "application/x-www-form-urlencoded", "\(connection.requestParams)")
		}
	}

	func testWebConnectionHeadersLF() {
		let connection = HTTPServer.HTTPWebConnection()

		let fullHeaders = "GET / HTTP/1.1\nX-Foo: bar\nX-Bar: \nContent-Type: application/x-www-form-urlencoded\n\n"

		connection.workingBuffer = UTF8Encoding.decode(string: fullHeaders)

		connection.scanWorkingBuffer {
			ok in

			XCTAssertTrue(ok)

			XCTAssertTrue(connection.requestParams["HTTP_X_FOO"] == "bar", "\(connection.requestParams)")
			XCTAssertTrue(connection.requestParams["HTTP_X_BAR"] == "", "\(connection.requestParams)")
			XCTAssertTrue(connection.contentType == "application/x-www-form-urlencoded", "\(connection.requestParams)")
		}
	}

	func testWebConnectionHeadersMalormed() {
		let connection = HTTPServer.HTTPWebConnection()

		let fullHeaders = "GET / HTTP/1.1\r\nX-Foo: bar\rX-Bar: \r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n"

		connection.workingBuffer = UTF8Encoding.decode(string: fullHeaders)

		connection.scanWorkingBuffer {
			ok in

			XCTAssertFalse(ok)
		}
	}

	func testWebConnectionHeadersFolded() {
		let connection = HTTPServer.HTTPWebConnection()

		let fullHeaders = "GET / HTTP/1.1\r\nX-Foo: bar\r\n bar\r\nX-Bar: foo\r\n  foo\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n"

		connection.workingBuffer = UTF8Encoding.decode(string: fullHeaders)

		connection.scanWorkingBuffer {
			ok in

			XCTAssertTrue(ok)

			XCTAssertTrue(connection.requestParams["HTTP_X_FOO"] == "barbar", "\(connection.requestParams)")
			XCTAssertTrue(connection.requestParams["HTTP_X_BAR"] == "foo foo", "\(connection.requestParams)")
			XCTAssertTrue(connection.contentType == "application/x-www-form-urlencoded", "\(connection.requestParams)")
		}

        let request = WebRequest(connection)

        XCTAssertTrue(request.headers["X-BAR"] == "foo foo", "\(request.headers)")
	}

	func testWebConnectionHeadersTooLarge() {
		let connection = HTTPServer.HTTPWebConnection()

		var fullHeaders = "GET / HTTP/1.1\r\nX-Foo:"
		for _ in 0..<(1024*10) {
			fullHeaders.append(" bar")
		}
		fullHeaders.append("\r\n\r\n")

		connection.workingBuffer = UTF8Encoding.decode(string: fullHeaders)

		connection.scanWorkingBuffer {
			ok in

			XCTAssertFalse(ok)

			XCTAssertTrue(connection.getStatus().0 == 413)
		}
	}

    private class ShimWebConnection: WebConnection {
        let connection = NetTCP()
        var requestParams = [String:String]()
        var stdin: [UInt8]?
        var mimes: MimeReader?
        var status = (0, "")

        func setStatus(code c: Int, message: String) { self.status = (c, message) }
        func getStatus() -> (Int, String) { return self.status }
        func writeHeader(line l: String) {}
        func writeHeader(bytes b: [UInt8], completion: (Bool) -> ()) { completion(true) }
        func writeBody(bytes b: [UInt8], completion: (Bool) -> ()) { completion(true) }
    }

    func testRoutingFound() {
        Routing.Routes["/foo/bar/baz"] = { _, _ in }
        let conn = ShimWebConnection()
        let req = WebRequest(conn)
        let resp = WebResponse(conn, request: req)
        let fnd = Routing.Routes["/foo/bar/baz", resp]

        XCTAssert(fnd != nil)
    }

    func testRoutingNotFound() {
        Routing.Routes["/foo/bar/baz"] = { _, _ in }
        let conn = ShimWebConnection()
        let req = WebRequest(conn)
        let resp = WebResponse(conn, request: req)
        let fnd = Routing.Routes["/foo/bar/buck", resp]

        XCTAssert(fnd == nil)
    }

    func testRoutingWild() {
        Routing.Routes["/foo/*/baz/*"] = { _, _ in }
        let conn = ShimWebConnection()
        let req = WebRequest(conn)
        let resp = WebResponse(conn, request: req)
        let fnd = Routing.Routes["/foo/bar/baz/bum", resp]

        XCTAssert(fnd != nil)
    }

    func testRoutingTrailingWild1() {
        Routing.Routes["/foo/**"] = { _, _ in }
        let conn = ShimWebConnection()
        let req = WebRequest(conn)
        let resp = WebResponse(conn, request: req)
        do {
            let fnd = Routing.Routes["/foo/bar/baz/bum", resp]
            XCTAssert(fnd != nil)
        }

        do {
            let fnd = Routing.Routes["/foo/bar", resp]
            XCTAssert(fnd != nil)
        }

        do {
            let fnd = Routing.Routes["/foo/", resp]
            XCTAssert(fnd != nil)
        }

        do {
            let fnd = Routing.Routes["/fooo/", resp]
            XCTAssert(fnd == nil)
        }
    }

    func testRoutingTrailingWild2() {
        Routing.Routes["**"] = { _, _ in }
        let conn = ShimWebConnection()
        let req = WebRequest(conn)
        let resp = WebResponse(conn, request: req)
        do {
            let fnd = Routing.Routes["/foo/bar/baz/bum", resp]
            XCTAssert(fnd != nil)
        }

        do {
            let fnd = Routing.Routes["/foo/bar", resp]
            XCTAssert(fnd != nil)
        }

        do {
            let fnd = Routing.Routes["/foo/", resp]
            XCTAssert(fnd != nil)
        }
    }

    func testRoutingVars() {
        Routing.Routes["/foo/{bar}/baz/{bum}"] = { _, _ in }
        let conn = ShimWebConnection()
        let req = WebRequest(conn)
        let resp = WebResponse(conn, request: req)
        let fnd = Routing.Routes["/foo/1/baz/2", resp]

        XCTAssert(fnd != nil)
        XCTAssert(req.urlVariables["bar"] == "1")
        XCTAssert(req.urlVariables["bum"] == "2")
    }

    func testRoutingAddPerformance() {
        self.measure {
            for i in 0..<10000 {
                Routing.Routes["/foo/\(i)/baz"] = { _, _ in }
            }
        }
    }

    func testDeletingPathExtension() {
        let path = "/a/b/c.txt"
        let del = path.stringByDeletingPathExtension
        XCTAssert("/a/b/c" == del)
    }

    func testGetPathExtension() {
        let path = "/a/b/c.txt"
        let ext = path.pathExtension
        XCTAssert("txt" == ext)
    }

    func testRoutingFindPerformance() {
        for i in 0..<10000 {
            Routing.Routes["/foo/\(i)/baz"] = { _, _ in }
        }

        let conn = ShimWebConnection()
        let req = WebRequest(conn)
        let resp = WebResponse(conn, request: req)

        self.measure {
            for i in 0..<10000 {
                guard let _ = Routing.Routes["/foo/\(i)/baz", resp] else {
                    XCTAssert(false, "Failed to find route")
                    break
                }
            }
        }
    }

    func testMimeReader() {

        let boundary = "----9051914041544843365972754266"

        var testData = Array<Dictionary<String, String>>()
        let numTestFields = 1 + _rand(to: 100)

        for idx in 0..<numTestFields {
            var testDic = Dictionary<String, String>()

            testDic["name"] = "test_field_\(idx)"

            let isFile = _rand(to: 3) == 2
            if isFile {
                var testValue = ""
                for _ in 1..<_rand(to: 1000) {
                    testValue.append("O")
                }
                testDic["value"] = testValue
                testDic["file"] = "1"
            } else {
                var testValue = ""
                for _ in 0..<_rand(to: 1000) {
                    testValue.append("O")
                }
                testDic["value"] = testValue
            }

            testData.append(testDic)
        }

        let file = File("/tmp/mimeReaderTest.txt")
        do {

            try file.open(.truncate)

            for testDic in testData {
                let _ = try file.write(string: "--" + boundary + "\r\n")

                let testName = testDic["name"]!
                let testValue = testDic["value"]!
                let isFile = testDic["file"]

                if let _ = isFile {

                    let _ = try file.write(string: "Content-Disposition: form-data; name=\"\(testName)\"; filename=\"\(testName).txt\"\r\n")
                    let _ = try file.write(string: "Content-Type: text/plain\r\n\r\n")
                    let _ = try file.write(string: testValue)
                    let _ = try file.write(string: "\r\n")

                } else {

                    let _ = try file.write(string: "Content-Disposition: form-data; name=\"\(testName)\"\r\n\r\n")
                    let _ = try file.write(string: testValue)
                    let _ = try file.write(string: "\r\n")
                }

            }

            let _ = try file.write(string: "--" + boundary + "--")

            for num in 1...2048 {

                file.close()
                try file.open()

                //print("Test run: \(num) bytes with \(numTestFields) fields")

                let mimeReader = MimeReader("multipart/form-data; boundary=" + boundary)

                XCTAssertEqual(mimeReader.boundary, "--" + boundary)

                var bytes = try file.readSomeBytes(count: num)
                while bytes.count > 0 {
                    mimeReader.addToBuffer(bytes: bytes)
                    bytes = try file.readSomeBytes(count: num)
                }

                XCTAssertEqual(mimeReader.bodySpecs.count, testData.count)

                var idx = 0
                for body in mimeReader.bodySpecs {

                    let testDic = testData[idx]
                    idx += 1
                    XCTAssertEqual(testDic["name"]!, body.fieldName)
                    if let _ = testDic["file"] {

                        let file = File(body.tmpFileName)
                        try file.open()
                        let contents = try file.readSomeBytes(count: file.size)
                        file.close()

                        let decoded = UTF8Encoding.encode(bytes: contents)
                        let v = testDic["value"]!
                        XCTAssertEqual(v, decoded)
                    } else {
                        XCTAssertEqual(testDic["value"]!, body.fieldValue)
                    }

                    body.cleanup()
                }
            }

            file.close()
            file.delete()

        } catch let e {
            XCTAssert(false, "\(e)")
        }
    }

    func testWebRequestQueryParam() {
        let req = WebRequest(HTTPServer.HTTPWebConnection())
        req.queryString = "yabba=dabba&doo=fi+☃&fi=&fo=fum"
        XCTAssert(req.param(name: "doo") == "fi ☃")
        XCTAssert(req.param(name: "fi") == "")
    }

    func testWebRequestPostParam() {
        let con = HTTPServer.HTTPWebConnection()
        let req = WebRequest(con)
        con.stdin = Array("yabba=dabba&doo=fi+☃&fi=&fo=fum".utf8)
        XCTAssert(req.param(name: "doo") == "fi ☃")
        XCTAssert(req.param(name: "fi") == "")
    }

    func testWebRequestCookie() {
        let req = WebRequest(HTTPServer.HTTPWebConnection())
        req.httpCookie = "yabba=dabba; doo=fi☃; fi=; fo=fum"
        for cookie in req.cookies {
            if cookie.0 == "doo" {
                XCTAssert(cookie.1 == "fi☃")
            }
            if cookie.0 == "fi" {
                XCTAssert(cookie.1 == "")
            }
        }
    }
}

extension PerfectLibTests {
    static var allTests : [(String, (PerfectLibTests) -> () throws -> Void)] {
        return [
					("testConcurrentQueue", testConcurrentQueue),
					("testSerialQueue", testSerialQueue),
					("testJSONConvertibleObject", testJSONConvertibleObject),
					("testJSONEncodeDecode", testJSONEncodeDecode),
					("testJSONDecodeUnicode", testJSONDecodeUnicode),
					("testNetSendFile", testNetSendFile),
					("testSysProcess", testSysProcess),
					("testStringByEncodingHTML", testStringByEncodingHTML),
					("testStringByEncodingURL", testStringByEncodingURL),
					("testStringByDecodingURL", testStringByDecodingURL),
					("testStringByDecodingURL2", testStringByDecodingURL2),
					("testStringByReplacingString", testStringByReplacingString),
					("testStringByReplacingString2", testStringByReplacingString2),
					("testStringByReplacingString3", testStringByReplacingString3),
					("testSubstringTo", testSubstringTo),
					("testRangeTo", testRangeTo),
					("testSubstringWith", testSubstringWith),
					("testICUFormatDate", testICUFormatDate),
					("testMustacheParser1", testMustacheParser1),
					("testHPACKEncode", testHPACKEncode),
					("testWebConnectionHeadersWellFormed", testWebConnectionHeadersWellFormed),
					("testWebConnectionHeadersLF", testWebConnectionHeadersLF),
					("testWebConnectionHeadersMalormed", testWebConnectionHeadersMalormed),
					("testWebConnectionHeadersFolded", testWebConnectionHeadersFolded),
					("testWebConnectionHeadersTooLarge", testWebConnectionHeadersTooLarge),
					("testMimeReader", testMimeReader),

					("testRoutingFound", testRoutingFound),
					("testRoutingNotFound", testRoutingNotFound),
					("testRoutingWild", testRoutingWild),
					("testRoutingVars", testRoutingVars),
					("testRoutingAddPerformance", testRoutingAddPerformance),
					("testRoutingFindPerformance", testRoutingFindPerformance),
					("testRoutingTrailingWild1", testRoutingTrailingWild1),
					("testRoutingTrailingWild2", testRoutingTrailingWild2),

					("testMimeReaderSimple", testMimeReaderSimple),
					("testDeletingPathExtension", testDeletingPathExtension),
					("testGetPathExtension", testGetPathExtension),

					("testWebRequestQueryParam", testWebRequestQueryParam),
					("testWebRequestCookie", testWebRequestCookie),
					("testWebRequestPostParam", testWebRequestPostParam)
        ]
    }
}
