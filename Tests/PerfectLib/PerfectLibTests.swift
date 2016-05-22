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
@testable import PerfectLib
import cURL

class PerfectLibTests: XCTestCase {
	
	override func setUp() {
		super.setUp()
		Foundation.srand(UInt32(time(nil)))
		// Put setup code here. This method is called before the invocation of each test method in the class.
		NetEvent.initialize()
	}
	
	override func tearDown() {
		// Put teardown code here. This method is called after the invocation of each test method in the class.
		super.tearDown()
	}
	
	#if swift(>=3.0)
	#else
	func measure(block: ()->()) {
		self.measureBlock(block)
	}
	#endif
	
	func testConcurrentQueue() {
		let q = Threading.getQueue(name: "concurrent", type: .Concurrent)
		
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
		let q = Threading.getQueue(name: "serial", type: .Serial)
		
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
	
	func _rand(to upper: Int32) -> Int32 {
		return Foundation.rand() % Int32(upper)
	}
	
	func testMimeReader() {
		
		let boundary = "---------------------------9051914041544843365972754266"
		
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
			
			try file.openTruncate()
			
			for testDic in testData {
				try file.write(string: "--" + boundary + "\r\n")
				
				let testName = testDic["name"]!
				let testValue = testDic["value"]!
				let isFile = testDic["file"]
				
				if let _ = isFile {
					
					try file.write(string: "Content-Disposition: form-data; name=\"\(testName)\"; filename=\"\(testName).txt\"\r\n")
					try file.write(string: "Content-Type: text/plain\r\n\r\n")
					try file.write(string: testValue)
					try file.write(string: "\r\n")
					
				} else {
					
					try file.write(string: "Content-Disposition: form-data; name=\"\(testName)\"\r\n\r\n")
					try file.write(string: testValue)
					try file.write(string: "\r\n")
				}
				
			}
			
			try file.write(string: "--" + boundary + "--")
			
			for num in 1...2048 {
				
				file.close()
				try file.openRead()
				
				print("Test run: \(num) bytes with \(numTestFields) fields")
				
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
						try file.openRead()
						let contents = try file.readSomeBytes(count: file.size())
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
			print("Exception while testing MimeReader: \(e)")
		}
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
			
			try file.openTruncate()
			
			for testDic in testData {
				try file.write(string: "--" + boundary + "\r\n")
				
				let testName = testDic["name"]!
				let testValue = testDic["value"]!
					
				try file.write(string: "Content-Disposition: form-data; name=\"\(testName)\"; filename=\"\(testName).txt\"\r\n")
				try file.write(string: "Content-Type: text/plain\r\n\r\n")
				try file.write(string: testValue)
				try file.write(string: "\r\n")
			}
			
			try file.write(string: "--" + boundary + "--")
			
			for num in 1...1 {
				
				file.close()
				try file.openRead()
				
				print("Test run: \(num) bytes with \(numTestFields) fields")
				
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
					try file.openRead()
					let contents = try file.readSomeBytes(count: file.size())
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
	
	func testClientServer() {
		
		let port = UInt16(6500)
		
		do {
			
			let server = NetTCP()
			let client = NetTCP()
			
			try server.bind(port: port, address: "127.0.0.1")
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
				guard let n = inn else {
					XCTAssertNotNil(inn)
					return
				}
				let b = Bytes()
				b.import8Bits(from: 1)
				do {
					n.write(bytes: b.data) {
						sent in
						
						XCTAssertTrue(sent == 1)
						
						n.readBytesFully(count: 1, timeoutSeconds: 5.0) {
							read in
							XCTAssert(read != nil)
							XCTAssert(read?.count == 1)
						}
						
						serverExpectation.fulfill()
					}
				}
			}
			
			try client.connect(address: "127.0.0.1", port: port, timeoutSeconds: 5) {
				(inn: NetTCP?) -> () in
				guard let n = inn else {
					XCTAssertNotNil(inn)
					return
				}
				let b = Bytes()
				b.import8Bits(from: 1)
				do {
					n.readBytesFully(count: 1, timeoutSeconds: 5.0) {
						read in
						
						XCTAssert(read != nil)
						XCTAssert(read!.count == 1)
						
						n.write(bytes: b.data) {
							sent in
							
							XCTAssertTrue(sent == 1)
							
							clientExpectation.fulfill()
						}
					}
				}
			}
		#if swift(>=3.0)
			self.waitForExpectations(withTimeout: 10000, handler: {
				_ in
				server.close()
				client.close()
			})
		#else
			self.waitForExpectationsWithTimeout(10000, handler: {
				_ in
				server.close()
				client.close()
			})
		#endif
			
		} catch PerfectError.NetworkError(let code, let msg) {
			XCTAssert(false, "Exception: \(code) \(msg)")
		} catch let e {
			XCTAssert(false, "Exception: \(e)")
		}
	}

	func testThreadSleep() {
		let now = getNow()
		Threading.sleep(seconds: 1.9)
		let nower = getNow()
		XCTAssert(nower - now >= 2.0)
	}
	
	func testClientServerReadTimeout() {
		
		let port = UInt16(6500)
		
		do {
			
			let server = NetTCP()
			let client = NetTCP()
			
			try server.bind(port: port, address: "127.0.0.1")
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
				guard let _ = inn else {
					XCTAssertNotNil(inn)
					return
				}
				Threading.sleep(seconds: 5)
				serverExpectation.fulfill()
			}
			
			var once = false
			try client.connect(address: "127.0.0.1", port: port, timeoutSeconds: 5) {
				(inn: NetTCP?) -> () in
				guard let n = inn else {
					XCTAssertNotNil(inn)
					return
				}
				let b = Bytes()
				b.import8Bits(from: 1)
				do {
					n.readBytesFully(count: 1, timeoutSeconds: 2.0) {
						read in
						
						XCTAssert(read == nil)
						XCTAssert(once == false)
						once = !once
						Threading.sleep(seconds: 7)
						XCTAssert(once == true)
						clientExpectation.fulfill()
					}
				}
			}
			
		#if swift(>=3.0)
			self.waitForExpectations(withTimeout: 10000, handler: {
				_ in
				server.close()
				client.close()
			})
		#else
			self.waitForExpectationsWithTimeout(10000, handler: {
				_ in
				server.close()
				client.close()
			})
		#endif
			
		} catch PerfectError.NetworkError(let code, let msg) {
			XCTAssert(false, "Exception: \(code) \(msg)")
		} catch let e {
			XCTAssert(false, "Exception: \(e)")
		}
	}
	
	func testNetSendFile() {
		
		let testFile = File("/tmp/file_to_send.txt")
		let testContents = "Here are the contents"
		let sock = "/tmp/foo.sock"
		let sockFile = File(sock)
		if sockFile.exists() {
			sockFile.delete()
		}
		
		do {
			
			try testFile.openTruncate()
			try testFile.write(string: testContents)
			testFile.close()
			try testFile.openRead()
			
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
							let testDataRead = try f!.readSomeBytes(count: f!.size())
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
			
		} catch PerfectError.NetworkError(let code, let msg) {
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
			
			print(UTF8Encoding.encode(bytes: data))
			let waitRes = try proc.wait()
			
			XCTAssertEqual(0, waitRes)
			
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
	
//	func testICUParseDate() {
//		let formatStr = "E, dd-MMM-yyyy HH:mm:ss 'GMT'"
//		do {
//			let result = try ICU.parseDate("Thu, 01-Jan-1970 00:00:00 GMT", format: formatStr, timezone: "GMT")
//			XCTAssertEqual(0, result)
//		} catch let e {
//			print("\(e)")
//			XCTAssert(false, "Exception running testICUParseDate")
//		}
//	}
	
	func testMustacheParser1() {
		let usingTemplate = "TOP {\n{{#name}}\n{{name}}{{/name}}\n}\nBOTTOM"
		do {
			let template = try MustacheParser().parse(string: usingTemplate)
			let d = ["name":"The name"] as [String:Any]
			let context = MustacheEvaluationContext(map: d)
			let collector = MustacheEvaluationOutputCollector()
			template.evaluate(context: context, collector: collector)
			
			XCTAssertEqual(collector.asString(), "TOP {\n\nThe name\n}\nBOTTOM")
		} catch {
			XCTAssert(false)
		}
	}
	
	func testCURL() {
		
		let url = "https://www.treefrog.ca"
		let curl = CURL(url: url)
		
		XCTAssert(curl.url == url)
		
		var header = [UInt8]()
		var body = [UInt8]()
		
		var perf = curl.perform()
		while perf.0 {
			if let h = perf.2 {
				header.append(contentsOf: h)
			}
			if let b = perf.3 {
				body.append(contentsOf: b)
			}
			perf = curl.perform()
		}
		if let h = perf.2 {
			header.append(contentsOf: h)
		}
		if let b = perf.3 {
			body.append(contentsOf: b)
		}
		let perf1 = perf.1
		XCTAssert(perf1 == 0)
		
		let response = curl.responseCode
		XCTAssert(response == 200)
		
		
		XCTAssert(header.count > 0)
		XCTAssert(body.count > 0)
		
		let headerStr = UTF8Encoding.encode(bytes: header)
		let bodyStr = UTF8Encoding.encode(bytes: body)
		
		print(headerStr)
		print(bodyStr)
	}
	
    func testCURLHeader() {
        let url = "https://httpbin.org/headers"
        let header = ("Accept", "application/json")
        
        let curl = CURL(url: url)
        curl.setOption(CURLOPT_HTTPHEADER, s: "\(header.0): \(header.1)" )
        let response = curl.performFully()
        XCTAssert(response.0 == 0)
        
        let body = UTF8Encoding.encode(bytes: response.2)
        do {
            guard
                let jsonMap = try body.jsonDecode() as? [String: Any],
                let headers = jsonMap["headers"] as? [String: Any],
                let accept = headers[header.0] as? String
            else {
                XCTAssert(false)
                return
            }
            XCTAssertEqual(accept, header.1)
        } catch let e {
            XCTAssert(false, "Exception: \(e)")
        }
    }

    func testCURLPost() {
        let url = "https://httpbin.org/post"
        let curl = CURL(url: url)
        
        curl.setOption(CURLOPT_POST, int: 1)
        
        let postParamString = "key1=value1&key2=value2"
        let byteArray = UTF8Encoding.decode(string: postParamString)
        curl.setOption(CURLOPT_POSTFIELDS, v: UnsafeMutablePointer<UInt8>(byteArray))
        curl.setOption(CURLOPT_POSTFIELDSIZE, int: byteArray.count)
        
        let response = curl.performFully()
        XCTAssert(response.0 == 0)
        
        let body = UTF8Encoding.encode(bytes: response.2)
        do {
            guard
                let jsonMap = try body.jsonDecode() as? [String: Any],
                let form = jsonMap["form"] as? [String: Any],
                let value1 = form["key1"] as? String,
                let value2 = form["key2"] as? String
            else {
                XCTAssert(false)
                return
            }
            XCTAssertEqual(value1, "value1")
            XCTAssertEqual(value2, "value2")
        } catch let e {
            XCTAssert(false, "Exception: \(e)")
        }
    }
	
    func testTCPSSLClient() {
		
		let address = "www.treefrog.ca"
		let requestString = [UInt8](("GET / HTTP/1.0\r\nHost: \(address)\r\n\r\n").utf8)
		let requestCount = requestString.count
	#if swift(>=3.0)
		let clientExpectation = self.expectation(withDescription: "client")
	#else
		let clientExpectation = self.expectationWithDescription("client")
	#endif
		let net = NetTCPSSL()
		
		let setOk = net.setDefaultVerifyPaths()
		XCTAssert(setOk, "Unable to setDefaultVerifyPaths \(net.sslErrorCode(resultCode: 1))")
		
		do {
			try net.connect(address: address, port: 443, timeoutSeconds: 5.0) {
				(net: NetTCP?) -> () in
				
				if let ssl = net as? NetTCPSSL {
					
					ssl.beginSSL {
						(success: Bool) in
						
						XCTAssert(success, "Unable to begin SSL \(ssl.errorStr(forCode: Int32(ssl.errorCode())))")
						if !success {
							clientExpectation.fulfill()
							return
						}
						
						do {
							let x509 = ssl.peerCertificate
							XCTAssert(x509 != nil)
							let peerKey = x509?.publicKeyBytes
							XCTAssert(peerKey != nil && peerKey!.count > 0)
						}
						
						ssl.write(bytes: requestString) {
							(sent:Int) -> () in
							
							XCTAssert(sent == requestCount)
							
							ssl.readBytesFully(count: 1, timeoutSeconds: 5.0) {
								(readBytes: [UInt8]?) -> () in
								
								XCTAssert(readBytes != nil && readBytes!.count > 0)
								
								let s1 = UTF8Encoding.encode(bytes: readBytes!)
								
								ssl.readSomeBytes(count: 4096) {
									(readBytes: [UInt8]?) -> () in
									
									XCTAssert(readBytes != nil && readBytes!.count > 0)
									
									let s = s1 + UTF8Encoding.encode(bytes: readBytes!)
									
									XCTAssert(s.begins(with: "HTTP/1.1 200 OK"))
									
									print(s)
									
									clientExpectation.fulfill()
								}
							}
						}
					}
				} else {
					XCTAssert(false, "Did not get NetTCPSSL back after connect")
				}
			}
		} catch {
			XCTAssert(false, "Exception thrown")
		}
		
	#if swift(>=3.0)
		self.waitForExpectations(withTimeout: 10000) {
			(_: NSError?) in
			net.close()
		}
	#else
		self.waitForExpectationsWithTimeout(10000) {
			(_: NSError?) in
			net.close()
		}
	#endif
	}
	
//	func testStringByResolvingSymlinksInPath() { // YMMV tmp is a link on OSX
//		// !FIX! this is currently failing //private/tmp
//		let path = "/tmp".stringByResolvingSymlinksInPath
//		XCTAssert(path == "/private/tmp")
//	}
	
	func testStringLastComponent() {
		XCTAssert("/a/".lastPathComponent == "a")
		XCTAssert("/b/a".lastPathComponent == "a")
		XCTAssert("/".lastPathComponent == "/")
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
	
	func testStringByDeletingLastPathComponent() {
		XCTAssert("/a/".stringByDeletingLastPathComponent == "/")
		XCTAssert("/b/a".stringByDeletingLastPathComponent == "/b")
		XCTAssert("/".stringByDeletingLastPathComponent == "/")
	}
	
	func testPathComponentsExPerformance() {
		let s = "/foo/bar/baz/bilbo/bucket/salami"
		self.measure {
			for _ in 0..<10000 {
				s.pathComponents.count
			}
		}
	}
	
	func testPathComponentsNatPerformance() {
		let s = "/foo/bar/baz/bilbo/bucket/salami" as NSString
		self.measure {
			for _ in 0..<10000 {
				s.pathComponents.count
			}
		}
	}
	
	func testPathComponentsSplitPerformance() {
		let s = "/foo/bar/baz/bilbo/bucket/salami"
		self.measure {
			
			for _ in 0..<10000 {
				s.characters.split(separator: Character("/")).map { String($0) } .count
			}
			
		}
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
}













