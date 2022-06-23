//
//  TypedRoutes.swift
//  PerfectHTTP
//
//  Created by Kyle Jessup on 2017-12-18.
//

import Foundation
import PerfectThread

extension HTTPResponseStatus: Codable {
	/// Codable support for HTTPResponseStatus
	public init(from decoder: Decoder) throws {
		self = HTTPResponseStatus.statusFrom(code: try Int(from: decoder))
	}
	/// Codable support for HTTPResponseStatus
	public func encode(to encoder: Encoder) throws {
		try code.encode(to: encoder)
	}
}

/// A codable response type indicating an error.
public struct HTTPResponseError: Error, Codable {
	/// The HTTP status for the response.
	public let status: HTTPResponseStatus
	/// Textual description of the error.
	public let description: String
	/// Init with status and description.
	public init(status s: HTTPResponseStatus, description d: String) {
		status = s
		description = d
	}
}

public protocol HTTPResponseContentProvider {
	func provide(response: HTTPResponse) throws -> HTTPResponse
}

/// Return content which has a chance to modify the response, set status or add headers.
public struct HTTPResponseContent<BodyType: Codable>: HTTPResponseContentProvider {
	public let status: HTTPResponseStatus
	public let responseHeaders: [(HTTPResponseHeader.Name, String)]
	public let body: BodyType
	public let finalFilter: ((HTTPResponse) -> ())?
	public init(status: HTTPResponseStatus = .ok, responseHeaders: [(HTTPResponseHeader.Name, String)] = [], body: BodyType, finalFilter: ((HTTPResponse) -> ())? = nil) {
		self.status = status
		self.responseHeaders = responseHeaders
		self.body = body
		self.finalFilter = finalFilter
	}
	public func provide(response: HTTPResponse) throws -> HTTPResponse {
		response.status = status
		try response.encode(body)
		responseHeaders.forEach { response.setHeader($0.0, value: $0.1) }
		finalFilter?(response)
		return response
	}
}

/// Return no content with a chance to modify the response, set status or add headers.
public struct HTTPResponseNoContent: HTTPResponseContentProvider {
	public let status: HTTPResponseStatus
	public let responseHeaders: [(HTTPResponseHeader.Name, String)]
	public let finalFilter: ((HTTPResponse) -> ())?
	public init(status: HTTPResponseStatus = .ok, responseHeaders: [(HTTPResponseHeader.Name, String)] = [], finalFilter: ((HTTPResponse) -> ())? = nil) {
		self.status = status
		self.responseHeaders = responseHeaders
		self.finalFilter = finalFilter
	}
	public func provide(response: HTTPResponse) throws -> HTTPResponse {
		response.status = status
		responseHeaders.forEach { response.setHeader($0.0, value: $0.1) }
		finalFilter?(response)
		return response
	}
}

private let lastObjectKey = "_last_object_"

/// Extensions on HTTPRequest which permit the request body to be decoded to a Codable type.
public extension HTTPRequest {
	/// Decode the request body into the desired type, or throw an error.
	func decode<A: Decodable>(_ type: A.Type) throws -> A {
		return try decode()
	}
	/// Decode the request body into the desired type, or throw an error.
	func decode<A: Decodable>() throws -> A {
		if let contentType = header(.contentType), contentType.hasPrefix("application/json") {
			guard let body = postBodyBytes else {
				throw DecodingError.dataCorrupted(.init(codingPath: [], debugDescription: "This request requires JSON input."))
			}
			// this is not exactly ideal
			// fudging url vars and json post body is inefficient
			let data: Data
			if !urlVariables.isEmpty,
				var dict = try JSONSerialization.jsonObject(with: Data(body), options: []) as? [String: Any] {
				urlVariables.forEach {
					let (key, value) = $0
					dict[key] = value
				}
				data = try JSONSerialization.data(withJSONObject: dict, options: [])
			} else {
				data = Data(body)
			}
			do {
				return try JSONDecoder().decode(A.self, from: data)
			} catch let error as DecodingError
				where error.localizedDescription == "The data couldn’t be read because it is missing." {
				throw HTTPResponseError(status: .badRequest, description: "Error while decoding request object. This is usually caused by API misuse. Check your request input names.")
			}
		} else {
			return try A.init(from: RequestDecoder(request: self))
		}
	}
	func decode() throws -> Self {
		return self
	}
    // swiftlint:disable force_cast
	internal func getInput<T>() throws -> T {
		if T.self == HTTPRequest.self {
			return self as! T
		} else {
			guard let input = scratchPad[lastObjectKey] as? T else {
				throw HTTPResponseError(status: .internalServerError, description: "No input object for handler.")
			}
			return input
		}
	}
}

extension HTTPResponse {
	public func handleError(error: Error) {
		do {
			switch error {
			case let error as HTTPResponseError:
				try encode(error).completed(status: error.status)
			case let error as CustomStringConvertible:
				let responseError = HTTPResponseError(status: .internalServerError, description: error.description)
				try encode(responseError).completed(status: .internalServerError)
			default:
				let desc = Array(error.localizedDescription.utf8)
				setBody(bytes: desc)
					.setHeader(.contentLength, value: "\(desc.count)")
					.completed(status: .internalServerError)
			}
		} catch _ {
			let desc = Array("\(error)".utf8)
			setBody(bytes: desc)
				.setHeader(.contentLength, value: "\(desc.count)")
				.completed(status: .internalServerError)
		}
	}
	@discardableResult
	func encode<A: Encodable>(_ t: A) throws -> Self {
		let tryJson = try JSONEncoder().encode(t)
		setBody(bytes: Array(tryJson))
			.setHeader(.contentType, value: MimeType(type: .application, subType: "json").longType)
			.setHeader(.contentLength, value: "\(tryJson.count)")
		return self
	}
}

protocol TypedRouteProtocol {
	var methods: [HTTPMethod] { get }
	var uri: String { get }
	var handler: RequestHandler { get }
	var route: Route { get }
}

protocol TypedRoutesProtocol {
	var baseUri: String { get }
	var handler: RequestHandler { get }
	var children: [TypedRouteProtocol] { get }
	var routes: Routes { get }
}

/// A typed intermediate route handler parameterized on the input and output types.
public struct TRoutes<I, O>: TypedRoutesProtocol {
	/// Input type alias
	public typealias InputType = I
	/// Output type alias
	public typealias OutputType = O
	let baseUri: String
	let typedHandler: (InputType) throws -> OutputType
	var children: [TypedRouteProtocol] = []
	var subRoutes: [TypedRoutesProtocol] = []
	var routes: Routes {
		var ret = Routes(baseUri: baseUri, handler: handler)
		for child in children {
			ret.add(child.route)
		}
		for route in subRoutes {
			ret.add(route.routes)
		}
		return ret
	}
	var handler: RequestHandler {
		return { req, resp in
			do {
				let input: InputType = try req.getInput()
				req.scratchPad[lastObjectKey] = try self.typedHandler(input)
				resp.next()
			} catch {
				resp.handleError(error: error)
			}
		}
	}
	init(baseUri u: String, handler t: @escaping (InputType) throws -> OutputType, children c: [TypedRouteProtocol]) {
		baseUri = u
		typedHandler = t
		children = c
	}
	/// Init with a base URI and handler.
	public init(baseUri u: String, handler t: @escaping (InputType) throws -> OutputType) {
		baseUri = u
		typedHandler = t
		children = []
	}
	/// Add a typed route to this base URI.
	@discardableResult
	public mutating func add(_ route: TRoute<OutputType>) -> TRoutes {
		children.append(route)
		return self
	}
	/// Add other intermediate routes to this base URI.
	@discardableResult
	public mutating func add<N>(_ route: TRoutes<OutputType, N>) -> TRoutes {
		subRoutes.append(route)
		return self
	}
}

/// A typed route handler.
public struct TRoute<I>: TypedRouteProtocol {
	/// Input type alias.
	public typealias InputType = I
	let methods: [HTTPMethod]
	let uri: String
	let typedHandler: ((InputType) throws -> HTTPResponseContentProvider)?
	let promiseHandler: RequestHandler?
	var route: Route {
		return .init(methods: methods, uri: uri, handler: handler)
	}
	var handler: RequestHandler {
		if let h = promiseHandler {
			return h
		}
		return { req, resp in
			do {
				let input: InputType = try req.getInput()
				try self.typedHandler?(input).provide(response: resp).completed()
			} catch {
				resp.handleError(error: error)
			}
		}
	}
	/// Init with a method, uri, and handler.
	/// Handler returning a Codable which will be JSON encoded.
	public init<OutputType: Codable>(method m: HTTPMethod, uri u: String, handler t: @escaping (InputType) throws -> OutputType) {
		self.init(methods: [m], uri: u, handler: t)
	}
	/// Init with zero or more methods, a uri, and handler.
	/// Handler returning a Codable which will be JSON encoded.
	public init<OutputType: Codable>(methods m: [HTTPMethod] = [.get, .post], uri u: String, handler t: @escaping (InputType) throws -> OutputType) {
		methods = m
		uri = u
		typedHandler = {
			return HTTPResponseContent<OutputType>(body: try t($0))
		}
		promiseHandler = nil
	}
	/// Init with a method, uri, and handler.
	/// Handler returning no content.
	public init(method m: HTTPMethod, uri u: String, handler t: @escaping (InputType) throws -> ()) {
		self.init(methods: [m], uri: u, handler: t)
	}
	/// Init with zero or more methods, a uri, and handler.
	/// Handler returning no content.
	public init(methods m: [HTTPMethod] = [.get, .post], uri u: String, handler t: @escaping (InputType) throws -> ()) {
		methods = m
		uri = u
		typedHandler = {
			try t($0)
			return HTTPResponseNoContent()
		}
		promiseHandler = nil
	}
	/// Init with a method, uri, and handler.
	// Handler returning HTTPResponseContentProvider.
	public init<P: HTTPResponseContentProvider>(method m: HTTPMethod, uri u: String, handler t: @escaping (InputType) throws -> P) {
		self.init(methods: [m], uri: u, handler: t)
	}
	/// Init with zero or more methods, a uri, and handler.
	/// Handler returning HTTPResponseContentProvider.
	public init<P: HTTPResponseContentProvider>(methods m: [HTTPMethod] = [.get, .post], uri u: String, handler t: @escaping (InputType) throws -> P) {
		methods = m
		uri = u
		typedHandler = t
		promiseHandler = nil
	}
	/// Init with a method, uri, and handler.
	// Handler returning Promise<HTTPResponseContentProvider>.
	public init<C: HTTPResponseContentProvider>(method m: HTTPMethod, uri u: String, handler t: @escaping (InputType, Promise<C>) -> ()) {
		self.init(methods: [m], uri: u, handler: t)
	}
	/// Init with zero or more methods, a uri, and handler.
	/// Handler returning Promise<HTTPResponseContentProvider>.
	public init<C: HTTPResponseContentProvider>(methods m: [HTTPMethod] = [.get, .post], uri u: String, handler t: @escaping (InputType, Promise<C>) -> ()) {
		methods = m
		uri = u
		typedHandler = nil
		promiseHandler = { req, resp in
			_ = Promise<C> { (promise: Promise<C>) in
				let input: InputType = try req.getInput()
				t(input, promise)
			}.then { content in
				try content().provide(response: resp).completed()
			}.when { error in
				resp.handleError(error: error)
			}
		}
	}
}

public extension TRoutes {
	/// Add a route to this object. The new route will take the output of this route as its input.
	@discardableResult
	mutating func add<N: Codable>(method m: HTTPMethod, uri u: String, handler t: @escaping (OutputType) throws -> N) -> TRoutes {
		return add(TRoute(method: m, uri: u, handler: t))
	}
	/// Add a route to this object. The new route will take the output of this route as its input.
	@discardableResult
	mutating func add(method m: HTTPMethod, uri u: String, handler t: @escaping (OutputType) throws -> ()) -> TRoutes {
		return add(TRoute(method: m, uri: u, handler: t))
	}
	/// Add a route to this object. The new route will take the output of this route as its input.
	@discardableResult
	mutating func add<P: HTTPResponseContentProvider>(method m: HTTPMethod, uri u: String, handler t: @escaping (OutputType) throws -> P) -> TRoutes {
		return add(TRoute(method: m, uri: u, handler: t))
	}
}

public extension Routes {
	/// Add routes to this object.
	mutating func add<I, O>(_ route: TRoutes<I, O>) {
		add(route.routes)
	}
	/// Add a route to this object.
	mutating func add<I>(_ route: TRoute<I>) {
		add(route.route)
	}
}

private enum SpecialType {
	case uint8Array, int8Array, data, uuid, date
	init?(_ type: Any.Type) {
		switch type {
		case is [Int8].Type:
			self = .int8Array
		case is [UInt8].Type:
			self = .uint8Array
		case is Data.Type:
			self = .data
		case is UUID.Type:
			self = .uuid
		case is Date.Type:
			self = .date
		default:
			return nil
		}
	}
}

private extension Date {
	func iso8601() -> String {
		let dateFormatter = DateFormatter()
		dateFormatter.locale = Locale(identifier: "en_US_POSIX")
		dateFormatter.timeZone = TimeZone(abbreviation: "GMT")
		dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
		let ret = dateFormatter.string(from: self) + "Z"
		return ret
	}
	init?(fromISO8601 string: String) {
		let dateFormatter = DateFormatter()
		dateFormatter.locale = Locale(identifier: "en_US_POSIX")
		dateFormatter.timeZone = TimeZone.current
		dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
		if let d = dateFormatter.date(from: string) {
			self = d
			return
		}
		dateFormatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSSx"
		if let d = dateFormatter.date(from: string) {
			self = d
			return
		}
		return nil
	}
}

// - decoders all the way down
class RequestReader<K: CodingKey>: KeyedDecodingContainerProtocol {
	typealias Key = K
	var codingPath: [CodingKey] = []
	var allKeys: [Key] = []
	let parent: RequestDecoder
	let params: [(String, String)]
	let uploads: [MimeReader.BodySpec]?
	var request: HTTPRequest { return parent.request }
	init(_ p: RequestDecoder) {
		parent = p
		params = p.request.params()
		uploads = p.request.postFileUploads
	}
	func getValue<T: LosslessStringConvertible>(_ key: Key) throws -> T {
		let str: String
		let keyStr = key.stringValue
		if let v = request.urlVariables[keyStr] {
			str = v
		} else if let files = uploads, let found = files.first(where: {$0.fieldName == keyStr}) {
			str = found.fieldValue
		} else if let v = params.first(where: {$0.0 == keyStr}) {
			str = v.1
		} else {
			throw DecodingError.keyNotFound(key, .init(codingPath: codingPath, debugDescription: "Key \(keyStr) not found."))
		}
		guard let ret = T.init(str) else {
			throw DecodingError.dataCorruptedError(forKey: key, in: self, debugDescription: "Could not convert to \(T.self).")
		}
		return ret
	}
	func contains(_ key: Key) -> Bool {
		if let _: String = try? getValue(key) {
			return true
		}
		return false
	}
	func decodeNil(forKey key: Key) throws -> Bool {
		return !contains(key)
	}
	func decode(_ type: Bool.Type, forKey key: Key) throws -> Bool {
		return try getValue(key)
	}
	func decode(_ type: Int.Type, forKey key: Key) throws -> Int {
		return try getValue(key)
	}
	func decode(_ type: Int8.Type, forKey key: Key) throws -> Int8 {
		return try getValue(key)
	}
	func decode(_ type: Int16.Type, forKey key: Key) throws -> Int16 {
		return try getValue(key)
	}
	func decode(_ type: Int32.Type, forKey key: Key) throws -> Int32 {
		return try getValue(key)
	}
	func decode(_ type: Int64.Type, forKey key: Key) throws -> Int64 {
		return try getValue(key)
	}
	func decode(_ type: UInt.Type, forKey key: Key) throws -> UInt {
		return try getValue(key)
	}
	func decode(_ type: UInt8.Type, forKey key: Key) throws -> UInt8 {
		return try getValue(key)
	}
	func decode(_ type: UInt16.Type, forKey key: Key) throws -> UInt16 {
		return try getValue(key)
	}
	func decode(_ type: UInt32.Type, forKey key: Key) throws -> UInt32 {
		return try getValue(key)
	}
	func decode(_ type: UInt64.Type, forKey key: Key) throws -> UInt64 {
		return try getValue(key)
	}
	func decode(_ type: Float.Type, forKey key: Key) throws -> Float {
		return try getValue(key)
	}
	func decode(_ type: Double.Type, forKey key: Key) throws -> Double {
		return try getValue(key)
	}
	func decode(_ type: String.Type, forKey key: Key) throws -> String {
		return try getValue(key)
	}
    // swiftlint:disable force_cast
	func decode<T>(_ t: T.Type, forKey key: Key) throws -> T where T: Decodable {
		if let special = SpecialType(t) {
			switch special {
			case .uint8Array, .int8Array, .data:
				throw DecodingError.keyNotFound(key, .init(codingPath: codingPath,
														   debugDescription: "The data type \(t) is not supported for GET requests."))
			case .uuid:
				let str: String = try getValue(key)
				guard let uuid = UUID(uuidString: str) else {
					throw DecodingError.dataCorruptedError(forKey: key, in: self, debugDescription: "Could not convert to \(t).")
				}
				return uuid as! T
			case .date:
				// !FIX! need to support better formats
				let str: String = try getValue(key)
				guard let date = Date(fromISO8601: str) else {
					throw DecodingError.dataCorruptedError(forKey: key, in: self, debugDescription: "Could not convert to \(t).")
				}
				return date as! T
			}
		}
		throw DecodingError.keyNotFound(key, .init(codingPath: codingPath,
												   debugDescription: "The data type \(t) is not supported for GET requests."))
	}
	func nestedContainer<NestedKey>(keyedBy type: NestedKey.Type, forKey key: Key) throws -> KeyedDecodingContainer<NestedKey> where NestedKey: CodingKey {
		fatalError("Unimplimented")
	}
	func nestedUnkeyedContainer(forKey key: Key) throws -> UnkeyedDecodingContainer {
		fatalError("Unimplimented")
	}
	func superDecoder() throws -> Decoder {
		fatalError("Unimplimented")
	}
	func superDecoder(forKey key: Key) throws -> Decoder {
		fatalError("Unimplimented")
	}
}

class RequestUnkeyedReader: UnkeyedDecodingContainer, SingleValueDecodingContainer {
	let codingPath: [CodingKey] = []
	var count: Int? = 1
	var isAtEnd: Bool { return currentIndex != 0 }
	var currentIndex: Int = 0
	let parent: RequestDecoder
	var decodedType: Any.Type?
	var typeDecoder: RequestDecoder?
	init(parent p: RequestDecoder) {
		parent = p
	}
	func advance(_ t: Any.Type) {
		currentIndex += 1
		decodedType = t
	}
	func decodeNil() -> Bool {
		return false
	}
	func decode(_ type: Bool.Type) throws -> Bool {
		advance(type)
		return false
	}
	func decode(_ type: Int.Type) throws -> Int {
		advance(type)
		return 0
	}
	func decode(_ type: Int8.Type) throws -> Int8 {
		advance(type)
		return 0
	}
	func decode(_ type: Int16.Type) throws -> Int16 {
		advance(type)
		return 0
	}
	func decode(_ type: Int32.Type) throws -> Int32 {
		advance(type)
		return 0
	}
	func decode(_ type: Int64.Type) throws -> Int64 {
		advance(type)
		return 0
	}
	func decode(_ type: UInt.Type) throws -> UInt {
		advance(type)
		return 0
	}
	func decode(_ type: UInt8.Type) throws -> UInt8 {
		advance(type)
		return 0
	}
	func decode(_ type: UInt16.Type) throws -> UInt16 {
		advance(type)
		return 0
	}
	func decode(_ type: UInt32.Type) throws -> UInt32 {
		advance(type)
		return 0
	}
	func decode(_ type: UInt64.Type) throws -> UInt64 {
		advance(type)
		return 0
	}
	func decode(_ type: Float.Type) throws -> Float {
		advance(type)
		return 0
	}
	func decode(_ type: Double.Type) throws -> Double {
		advance(type)
		return 0
	}
	func decode(_ type: String.Type) throws -> String {
		advance(type)
		return ""
	}
	func decode<T: Decodable>(_ type: T.Type) throws -> T {
		advance(type)
		return try T(from: parent)
	}
	func nestedContainer<NestedKey>(keyedBy type: NestedKey.Type) throws -> KeyedDecodingContainer<NestedKey> where NestedKey: CodingKey {
		fatalError("Unimplimented")
	}
	func nestedUnkeyedContainer() throws -> UnkeyedDecodingContainer {
		fatalError("Unimplimented")
	}
	func superDecoder() throws -> Decoder {
		currentIndex += 1
		return parent
	}
}

class RequestDecoder: Decoder {
	var codingPath: [CodingKey] = []
	var userInfo: [CodingUserInfoKey: Any] = [:]
	let request: HTTPRequest
	init(request r: HTTPRequest) {
		request = r
	}
	func container<Key>(keyedBy type: Key.Type) throws -> KeyedDecodingContainer<Key> where Key: CodingKey {
		return KeyedDecodingContainer<Key>(RequestReader<Key>(self))
	}
	func unkeyedContainer() throws -> UnkeyedDecodingContainer {
		return RequestUnkeyedReader(parent: self)
	}
	func singleValueContainer() throws -> SingleValueDecodingContainer {
		return RequestUnkeyedReader(parent: self)
	}
}
