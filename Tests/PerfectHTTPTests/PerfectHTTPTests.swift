import XCTest
import PerfectNet
import PerfectLib
import Foundation
import Dispatch
import PerfectThread
@testable import PerfectHTTP

#if os(Linux)
	import SwiftGlibc
#endif

// random from 1 to upper, inclusive
func _rand(to upper: Int32) -> Int32 {
	#if os(Linux)
		return (SwiftGlibc.rand() % Int32(upper-1)) + 1
	#else
        // swiftlint:disable legacy_random
		return Int32(arc4random_uniform(UInt32(upper-1))) + 1
	#endif
}

class ShimHTTPRequest: HTTPRequest {
	var method = HTTPMethod.get
	var path = "/"
	var pathComponents: [String] { return [""] }
	var queryParams = [(String, String)]()
	var protocolVersion = (1, 1)
	var remoteAddress = (host: "127.0.0.1", port: 8000 as UInt16)
	var serverAddress = (host: "127.0.0.1", port: 8282 as UInt16)
	var serverName = "my_server"
	var documentRoot = "./webroot"
	var connection = NetTCP()
	var urlVariables = [String: String]()
	var scratchPad = [String: Any]()
	func header(_ named: HTTPRequestHeader.Name) -> String? { return nil }
	func addHeader(_ named: HTTPRequestHeader.Name, value: String) {}
	func setHeader(_ named: HTTPRequestHeader.Name, value: String) {}
	var headers = AnyIterator<(HTTPRequestHeader.Name, String)> { return nil }
	var postParams = [(String, String)]()
	var postBodyBytes: [UInt8]? = nil
	var postBodyString: String? = nil
	var postFileUploads: [MimeReader.BodySpec]? = nil
}
// swiftlint:disable syntactic_sugar
class ShimHTTPResponse: HTTPResponse {
	var request: HTTPRequest = ShimHTTPRequest()
	var status: HTTPResponseStatus = .ok
	var isStreaming = false
	var bodyBytes = [UInt8]()
	var headerStore = Array<(HTTPResponseHeader.Name, String)>()
	func header(_ named: HTTPResponseHeader.Name) -> String? {
		for (n, v) in headerStore where n == named {
			return v
		}
		return nil
	}
	@discardableResult
	func addHeader(_ name: HTTPResponseHeader.Name, value: String) -> Self {
		headerStore.append((name, value))
		return self
	}
	@discardableResult
	func setHeader(_ name: HTTPResponseHeader.Name, value: String) -> Self {
		var fi = [Int]()
		for i in 0..<headerStore.count {
			let (n, _) = headerStore[i]
			if n == name {
				fi.append(i)
			}
		}
		fi = fi.reversed()
		for i in fi {
			headerStore.remove(at: i)
		}
		return addHeader(name, value: value)
	}
	var headers: AnyIterator<(HTTPResponseHeader.Name, String)> {
		var g = self.headerStore.makeIterator()
		return AnyIterator<(HTTPResponseHeader.Name, String)> {
			g.next()
		}
	}
	func addCookie(_: PerfectHTTP.HTTPCookie) -> Self { return self }
	func appendBody(bytes: [UInt8]) { bodyBytes.append(contentsOf: bytes) }
	func appendBody(string: String) { appendBody(bytes: Array(string.utf8)) }
	func push(callback: @escaping (Bool) -> ()) {}
	func completed() {}
	func next() {
		if let f = handlers?.removeFirst() {
			f(request, self)
		}
	}

	// shim shim
	var handlers: [RequestHandler]?
}

// swiftlint:disable type_body_length
class PerfectHTTPTests: XCTestCase {

	override func setUp() {
		super.setUp()
	}
    // swiftlint:disable syntactic_sugar
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
				_ = try file.write(string: "--" + boundary + "\r\n")
				let testName = testDic["name"]!
				let testValue = testDic["value"]!
				_ = try file.write(string: "Content-Disposition: form-data; name=\"\(testName)\"; filename=\"\(testName).txt\"\r\n")
				_ = try file.write(string: "Content-Type: text/plain\r\n\r\n")
				_ = try file.write(string: testValue)
				_ = try file.write(string: "\r\n")
			}
			_ = try file.write(string: "--" + boundary + "--")
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
    // swiftlint:disable syntactic_sugar
	func testMimeReader() {

		let boundary = "----9051914041544843365972754266"

		var testData = [[String: String]]()
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
				try file.write(string: "--" + boundary + "\r\n")
				let testName = testDic["name"]!
				let testValue = testDic["value"]!
				let isFile = testDic["file"]
				if nil != isFile {
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
				try file.open()

				// print("Test run: \(num) bytes with \(numTestFields) fields")

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
					if nil != testDic["file"] {

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

	func testRoutingFound1() {
		let uri = "/foo/bar/baz"
		var r = Routes()
		r.add(method: .get, uri: uri, handler: { _, _ in })
		let req = ShimHTTPRequest()
		let fnd = r.navigator.findHandler(uri: uri, webRequest: req)
		XCTAssert(fnd != nil)
	}

	func testRoutingFound2() {
		let uri = "/foo/bar/baz"
		var r = Routes()
		r.add(uri: uri, handler: { _, _ in })
		let req = ShimHTTPRequest()
		do {
			let fnd = r.navigator.findHandler(uri: uri, webRequest: req)
			XCTAssert(fnd != nil)
		}
		req.method = .options
		do {
			let fnd = r.navigator.findHandler(uri: uri, webRequest: req)
			XCTAssert(fnd != nil)
		}
	}

	func testRoutingNotFound() {
		let uri = "/foo/bar/baz"
		var r = Routes()
		r.add(method: .get, uri: uri, handler: { _, _ in })
		let req = ShimHTTPRequest()
		let fnd = r.navigator.findHandler(uri: uri+"z", webRequest: req)
		XCTAssert(fnd == nil)
	}

	func testRoutingWild() {
		let uri = "/foo/*/baz/*"
		var r = Routes()
		r.add(method: .get, uri: uri, handler: { _, _ in })
		let req = ShimHTTPRequest()
		let fnd = r.navigator.findHandler(uri: "/foo/bar/baz/bum", webRequest: req)
		XCTAssert(fnd != nil)
	}

	func testRoutingTrailingSlash1() {
		let uri = "/foo/*/baz/"
		var r = Routes()
		r.add(method: .get, uri: uri, handler: { _, _ in })
		let req = ShimHTTPRequest()
		let fnd = r.navigator.findHandler(uri: "/foo/bar/baz/", webRequest: req)
		XCTAssert(fnd != nil)
		let fnd2 = r.navigator.findHandler(uri: "/foo/bar/baz", webRequest: req)
		XCTAssert(fnd2 == nil)
	}

	func testRoutingTrailingSlash2() {
		let uri = "/foo/*/baz"
		var r = Routes()
		r.add(method: .get, uri: uri, handler: { _, _ in })
		let req = ShimHTTPRequest()
		let fnd = r.navigator.findHandler(uri: "/foo/bar/baz/", webRequest: req)
		XCTAssert(fnd == nil)
		let fnd2 = r.navigator.findHandler(uri: "/foo/bar/baz", webRequest: req)
		XCTAssert(fnd2 != nil)
	}

	func testRoutingTrailingSlash3() {
		let uri1 = "/foo/bar/baz"
		let uri2 = "/foo/"
		var r = Routes()
		r.add(method: .get, uri: uri1, handler: { _, _ in })
		r.add(method: .get, uri: uri2, handler: { _, _ in })
		let req = ShimHTTPRequest()
		do {
			let fnd = r.navigator.findHandler(uri: "/foo/bar/baz/", webRequest: req)
			XCTAssert(fnd == nil)
		}
		do {
			let fnd = r.navigator.findHandler(uri: "/foo/bar/baz", webRequest: req)
			XCTAssert(fnd != nil)
		}
		do {
			let fnd = r.navigator.findHandler(uri: "/foo/", webRequest: req)
			XCTAssert(fnd != nil)
		}
		do {
			let fnd = r.navigator.findHandler(uri: "/foo", webRequest: req)
			XCTAssert(fnd == nil)
		}
	}

	func testRoutingTrailingSlash4() {
		var r = Routes()
		let badHandler = { (_: HTTPRequest, resp: HTTPResponse) in
			resp.status = .internalServerError
		}
		let goodHandler = { (_: HTTPRequest, resp: HTTPResponse) in
			resp.status = .notFound
		}
		r.add(method: .get, uri: "/", handler: { _, _ in })
		r.add(method: .get, uri: "/test/", handler: goodHandler)
		r.add(method: .get, uri: "/**", handler: badHandler)
		let resp = ShimHTTPResponse()
		do {
			let fnd = r.navigator.findHandler(uri: "/", webRequest: resp.request)
			XCTAssert(fnd != nil)
		}
		do {
			let fnd = r.navigator.findHandler(uri: "/test/", webRequest: resp.request)
			XCTAssert(fnd != nil)
			fnd?(resp.request, resp)
			guard case .notFound = resp.status else {
				return XCTAssert(false, "Wrong handler")
			}
		}
	}

	func testRoutingVars() {
		let uri = "/fOo/{bar}/baZ/{bum}"
		var r = Routes()
		r.add(method: .get, uri: uri, handler: { _, _ in })
		let req = ShimHTTPRequest()
		let fnd = r.navigator.findHandler(uri: "/Foo/1/Baz/2", webRequest: req)
		XCTAssert(fnd != nil)
		XCTAssert(req.urlVariables["bar"] == "1")
		XCTAssert(req.urlVariables["bum"] == "2")
	}

	func testRoutingVars2() {
		let uri = "/fOo/{bar}/baZ/{bum}"
		var r = Routes()
		r.add(method: .get, uri: uri, handler: { _, _ in })
		let req = ShimHTTPRequest()
		let fnd = r.navigator.findHandler(uri: "/Foo/ABC/Baz/abc", webRequest: req)
		XCTAssert(fnd != nil)
		XCTAssert(req.urlVariables["bar"] == "ABC")
		XCTAssert(req.urlVariables["bum"] == "abc")
	}

	func testRoutingTrailingWild1() {
		let uri = "/foo/**"
		var r = Routes()
		r.add(method: .get, uri: uri, handler: { _, _ in })
		let req = ShimHTTPRequest()
		do {
			let fnd = r.navigator.findHandler(uri: "/foo/bar/baz/bum", webRequest: req)
			XCTAssert(fnd != nil)
			XCTAssert(req.urlVariables[routeTrailingWildcardKey] == "/bar/baz/bum")
		}

		do {
			let fnd = r.navigator.findHandler(uri: "/foo/bar", webRequest: req)
			XCTAssert(fnd != nil)
		}

		do {
			let fnd = r.navigator.findHandler(uri: "/foo/", webRequest: req)
			XCTAssert(fnd != nil)
		}

		do {
			let fnd = r.navigator.findHandler(uri: "/fooo0/", webRequest: req)
			XCTAssert(fnd == nil)
		}
	}

	func testRoutingTrailingWild2() {
		let uri = "**"
		var r = Routes()
		r.add(method: .get, uri: uri, handler: { _, _ in })
		let req = ShimHTTPRequest()
		do {
			let fnd = r.navigator.findHandler(uri: "/foo/bar/baz/bum", webRequest: req)
			XCTAssert(fnd != nil)
			XCTAssert(req.urlVariables[routeTrailingWildcardKey] == "/foo/bar/baz/bum")
		}

		do {
			let fnd = r.navigator.findHandler(uri: "/foo/bar", webRequest: req)
			XCTAssert(fnd != nil)
		}

		do {
			let fnd = r.navigator.findHandler(uri: "/foo/", webRequest: req)
			XCTAssert(fnd != nil)
		}
	}

	func testRoutingMulti1() {

		var r = Routes(baseUri: "/a/b/{c}") { _, _ in
		}
		r.add(uri: "/1") { _, _ in
		}
		r.add(method: .get, uri: "/2") { _, _ in
		}
		r.add(method: .post, uri: "/2") { _, _ in
		}
		let req = ShimHTTPRequest()
		do {
			let fnd = r.navigator.findHandlers(uri: "/a/b/c/1", webRequest: req)
			XCTAssert(fnd != nil)
			XCTAssert(fnd?.count == 2)
		}
		do {
			let fnd = r.navigator.findHandlers(uri: "/a/b/c/2", webRequest: req)
			XCTAssert(fnd != nil)
			XCTAssert(fnd?.count == 2)
		}
	}

	func testRoutingMulti2() {

		var r = Routes()
		r.add(uri: "/") { _, _ in
		}
		r.add(method: .get, uri: "/1") { _, _ in
		}
		let req = ShimHTTPRequest()
		do {
			let fnd = r.navigator.findHandlers(uri: "/", webRequest: req)
			XCTAssert(fnd != nil)
			XCTAssert(fnd?.count == 1)
		}
		do {
			let fnd = r.navigator.findHandlers(uri: "/1", webRequest: req)
			XCTAssert(fnd != nil)
			XCTAssert(fnd?.count == 1)
		}
	}

	func testRoutingAddPerformance() {
		var r = Routes()
		self.measure {
			for i in 0..<10000 {
				r.add(method: .get, uri: "/foo/\(i)/baz", handler: { _, _ in })
			}
		}
	}

	func testRoutingFindPerformance() {
		var r = Routes()
		for i in 0..<10000 {
			r.add(method: .get, uri: "/foo/\(i)/baz", handler: { _, _ in })
		}
		let req = ShimHTTPRequest()
		let navigator = r.navigator
		self.measure {
			for i in 0..<10000 {
				guard nil != navigator.findHandler(uri: "/foo/\(i)/baz", webRequest: req) else {
					XCTAssert(false, "Failed to find route")
					break
				}
			}
		}
	}

	func testFormatDate() {
		let dateThen = 0.0
		let formatStr = "%a, %d-%b-%Y %T GMT"
		if let result = dateThen.formatDate(format: formatStr) {
			XCTAssertEqual(result, "Thu, 01-Jan-1970 00:00:00 GMT")
		} else {
			XCTAssert(false, "Bad date format")
		}
	}

	enum Province: Int, Codable {
		case ontario
	}
	struct SessionInfo: Codable {
		// ...could be an authentication token, etc.
		let id: String
	}
	struct RequestResponse: Codable {
		struct Address: Codable {
			let street: String
			let city: String
			let province: Province
			let country: String
			let postalCode: String
		}
		let fullName: String
		let address: Address
	}

	func testTypedRoutes() {
		// when handlers further down need the request you can pass it along. this is not nessesary though
		typealias RequestSession = (request: HTTPRequest, session: SessionInfo)
		func checkSession(request: HTTPRequest) throws -> RequestSession {
			// one would check the request to make sure it's authorized
			let sessionInfo = try request.decode(SessionInfo.self) // will throw if request does not include id
			return (request, sessionInfo)
		}

		func replyCodable(_ session: RequestSession) throws -> RequestResponse {
			return .init(fullName: "Justin Trudeau",
						 address: .init(street: "111 Wellington St",
										city: "Ottawa",
										province: .ontario,
										country: "Canada",
										postalCode: "K1A 0A6"))
		}
		func replyVoid(session: RequestSession) throws {}
		func replyContent(session: RequestSession) throws -> HTTPResponseContent<RequestResponse> {
			return .init(body: try replyCodable(session),
						 finalFilter: { r in r.setHeader(.contentType, value: "foo/bar") ; return })
		}
		func replyNoContent(session: RequestSession) throws -> HTTPResponseNoContent {
			return .init(responseHeaders: [(.contentType, "foo/bar")])
		}
		var routes = Routes() // root
		var apiRoutes = TRoutes(baseUri: "/api/", handler: checkSession)
		apiRoutes.add(method: .get, uri: "info1/{id}", handler: replyCodable)
		apiRoutes.add(method: .get, uri: "info2/{id}", handler: replyVoid)
		apiRoutes.add(method: .get, uri: "info3/{id}", handler: replyContent)
		apiRoutes.add(method: .get, uri: "info4/{id}", handler: replyNoContent)
		routes.add(apiRoutes)
		do {
			let request = ShimHTTPRequest()
			let response = ShimHTTPResponse()
			response.request = request
			request.method = .get
			let handlers = routes.navigator.findHandlers(uri: "/api/info1/abc123", webRequest: request)
			XCTAssertNotNil(handlers)
			XCTAssertNotEqual(handlers?.count, 0)
			response.handlers = handlers
			response.next()
			XCTAssertEqual(response.header(.contentType), "application/json")
			let decodeCheck = try? JSONDecoder().decode(RequestResponse.self, from: Data(response.bodyBytes))
			XCTAssertNotNil(decodeCheck)
		}
		do {
			let request = ShimHTTPRequest()
			let response = ShimHTTPResponse()
			response.request = request
			request.method = .get
			let handlers = routes.navigator.findHandlers(uri: "/api/info2/abc123", webRequest: request)
			XCTAssertNotNil(handlers)
			XCTAssertNotEqual(handlers?.count, 0)
			response.handlers = handlers
			response.next()
			XCTAssertEqual(response.bodyBytes.count, 0)
		}
		do {
			let request = ShimHTTPRequest()
			let response = ShimHTTPResponse()
			response.request = request
			request.method = .get
			let handlers = routes.navigator.findHandlers(uri: "/api/info3/abc123", webRequest: request)
			XCTAssertNotNil(handlers)
			XCTAssertNotEqual(handlers?.count, 0)
			response.handlers = handlers
			response.next()
			XCTAssertEqual(response.header(.contentType), "foo/bar")
			let decodeCheck = try? JSONDecoder().decode(RequestResponse.self, from: Data(response.bodyBytes))
			XCTAssertNotNil(decodeCheck)
		}
		do {
			let request = ShimHTTPRequest()
			let response = ShimHTTPResponse()
			response.request = request
			request.method = .get
			let handlers = routes.navigator.findHandlers(uri: "/api/info4/abc123", webRequest: request)
			XCTAssertNotNil(handlers)
			XCTAssertNotEqual(handlers?.count, 0)
			response.handlers = handlers
			response.next()
			XCTAssertEqual(response.bodyBytes.count, 0)
			XCTAssertEqual(response.header(.contentType), "foo/bar")
		}
	}

	func testTypedPromiseRoute() {
		var expect = expectation(description: "wait1")
		struct Body: Codable {
			let msg: String
		}

		func handleIt(req: HTTPRequest, promise: Promise<HTTPResponseContent<Body>>) {
			DispatchQueue.global().asyncAfter(deadline: .now() + 1) {
				promise.set(HTTPResponseContent(body: Body(msg: "Hi")))
				DispatchQueue.global().asyncAfter(deadline: .now() + 1) {
					expect.fulfill()
				}
			}
		}

		func failIt(req: HTTPRequest, promise: Promise<HTTPResponseContent<Body>>) {
			DispatchQueue.global().asyncAfter(deadline: .now() + 1) {
				promise.fail(HTTPResponseError(status: .badRequest, description: "Hi"))
				DispatchQueue.global().asyncAfter(deadline: .now() + 1) {
					expect.fulfill()
				}
			}
		}

		var routes = Routes() // root
		routes.add(TRoute<HTTPRequest>(method: .get, uri: "/info", handler: handleIt))
		routes.add(TRoute<HTTPRequest>(method: .get, uri: "/fail", handler: failIt))

		do {
			let request = ShimHTTPRequest()
			let response = ShimHTTPResponse()
			response.request = request
			request.method = .get
			let handlers = routes.navigator.findHandlers(uri: "/info", webRequest: request)
			XCTAssertNotNil(handlers)
			XCTAssertNotEqual(handlers?.count, 0)
			response.handlers = handlers
			response.next()
      		self.waitForExpectations(timeout: 10) { _ in }

			XCTAssertEqual(response.header(.contentType), "application/json")
			let decodeCheck = try? JSONDecoder().decode(Body.self, from: Data(response.bodyBytes))
			XCTAssertNotNil(decodeCheck)
		}

    	expect = expectation(description: "wait2")

		do {
			let request = ShimHTTPRequest()
			let response = ShimHTTPResponse()
			response.request = request
			request.method = .get
			let handlers = routes.navigator.findHandlers(uri: "/fail", webRequest: request)
			XCTAssertNotNil(handlers)
			XCTAssertNotEqual(handlers?.count, 0)
			response.handlers = handlers
			response.next()

			self.waitForExpectations(timeout: 10) { _ in }

			XCTAssert(response.status.code == HTTPResponseStatus.badRequest.code)
		}
	}

	func testMimeTypeComparison() {
		do {
			let lhs = MimeType("text/plain")
			let rhs = MimeType("text/plain")
			XCTAssert(lhs == rhs)
		}
		do {
			let lhs = MimeType("text/*")
			let rhs = MimeType("text/plain")
			XCTAssert(lhs == rhs)
		}
		do {
			let lhs = MimeType("text/plain")
			let rhs = MimeType("text/*")
			XCTAssert(lhs == rhs)
		}
		do {
			let lhs = MimeType("text/plain")
			let rhs = MimeType("*/*")
			XCTAssert(lhs == rhs)
		}
		do {
			let lhs = MimeType("text/plain")
			let rhs = MimeType("text/html")
			XCTAssert(lhs != rhs)
		}
		do {
			let lhs = MimeType("*/plain")
			let rhs = MimeType("text/plain")
			XCTAssert(lhs == rhs)
		}
		do {
			let lhs = MimeType("*/plain")
			let rhs = MimeType("text/html")
			XCTAssert(lhs != rhs)
		}
	}

	func testMimeForExtension() {
		XCTAssert(MimeType.forExtension("ts") == "video/mp2t")
	}

    func testErrorBodyInJson() {
        let response = ShimHTTPResponse()
        let errResp = HTTPResponseError(status: .badRequest, description: "invalid request")
        response.setBody(error: errResp)
        let data = Data(response.bodyBytes)
        struct ErrorCodable: Codable {
            let error: String
        }
        do {
            let e = try JSONDecoder().decode(ErrorCodable.self, from: data)
            XCTAssertEqual(e.error, "HTTPResponseError(status: 400 Bad Request, description: 'invalid request')")
        } catch {
            XCTFail("\(error)")
        }
    }

    func testErrorBodyIntext() {
        let response = ShimHTTPResponse()
        let errResp = HTTPResponseError(status: .badRequest, description: "invalid request")
        response.setBody(error: errResp, asJson: false)
        let data = Data(response.bodyBytes)
        guard let text = String(data: data, encoding: .utf8) else {
            XCTFail("unable to encode error body in text")
            return
        }
        XCTAssertEqual(text, "HTTPResponseError(status: 400 Bad Request, description: 'invalid request')")
    }

    func testJSONBody() {
		do {
			let response = ShimHTTPResponse()
			struct MyCodable: Codable {
				let id: Int
				let name: String
				let uu: Foundation.UUID
				let d: Date
			}
			let t1 = MyCodable(id: 1, name: "name", uu: UUID(), d: Date())
			try response.setBody(json: t1)

            let data = Data(response.bodyBytes)
            let t2 = try JSONDecoder().decode(MyCodable.self, from: data)
            XCTAssertEqual(t1.id, t2.id)
            XCTAssertEqual(t1.name, t2.name)
            XCTAssertEqual(t1.uu, t2.uu)
            XCTAssertEqual(t1.d, t2.d)
		} catch {
			XCTFail("\(error)")
		}

		do {
			let response = ShimHTTPResponse()
			let mc: [String: Any] = ["id": 1, "name": "name"]
			try response.setBody(json: mc)

			let t1 = Data(response.bodyBytes)
            let t2 = try JSONSerialization.jsonObject(with: t1) as? [String: Any]
			XCTAssertEqual(t2?["id"] as? Int, mc["id"] as? Int)
            XCTAssertEqual(t2?["name"] as? String, mc["name"] as? String)
		} catch {
			XCTFail("\(error)")
		}
	}

	func testHeaderHashValue() {
		do {
			let h1 = HTTPRequestHeader.Name.custom(name: "X-Foo")
			let h2 = HTTPRequestHeader.Name.custom(name: "X-Foo2")
			XCTAssertNotEqual(h1.hashValue, h2.hashValue)
		}
		do {
			let h1 = HTTPResponseHeader.Name.custom(name: "X-Foo")
			let h2 = HTTPResponseHeader.Name.custom(name: "X-Foo2")
			XCTAssertNotEqual(h1.hashValue, h2.hashValue)
		}
	}

	func testMethodHashValue() {
		let h1 = HTTPMethod.custom("X-Foo")
		let h2 = HTTPMethod.custom("X-Foo2")
		XCTAssertNotEqual(h1.hashValue, h2.hashValue)
	}
}
