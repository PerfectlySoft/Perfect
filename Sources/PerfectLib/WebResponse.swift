//
//  WebResponse.swift
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

/// This class bundles together the values which will be used to set a cookie in the outgoing response
public struct Cookie {
	public let name: String?
	public let value: String?
	public let domain: String?
	public let expires: String?
	public let expiresIn: Double // seconds from now. may be negative. 0.0 means no expiry (session cookie)
	public let path: String?
	public let secure: Bool?
	public let httpOnly: Bool?

	public init(name: String?,
		value: String?,
		domain: String?,
		expires: String?,
		expiresIn: Double,
		path: String?,
		secure: Bool?,
		httpOnly: Bool?) {
			self.name = name
			self.value = value
			self.domain = domain
			self.expires = expires
			self.expiresIn = expiresIn
			self.path = path
			self.secure = secure
			self.httpOnly = httpOnly
	}
}

/// Represents an outgoing web response. Handles the following tasks:
/// - Management of sessions
/// - Collecting HTTP response headers & cookies.
/// - Locating the response template file, parsing it, evaluating it and returning the resulting data.
/// - Provides access to the WebRequest object.
public class WebResponse {

	var connection: WebConnection

	/// The WebRequest for this response
	public var request: WebRequest
	/// The output encoding for a textual response. Defaults to UTF-8.
	public var outputEncoding = "UTF-8"

	var headersArray = [(String, String)]()
	var cookiesArray = [Cookie]()
	var includeStack = [String]()

	var appStatus = 0
	var appMessage = ""

	var bodyData = [UInt8]()

	public var requestCompleted: () -> () = {}

	internal init(_ c: WebConnection, request: WebRequest) {
		self.connection = c
		self.request = request
	}

	/// Set the response status code and message. For example, 200, "OK".
	public func setStatus(code c: Int, message m: String) {
		self.connection.setStatus(code: c, message: m)
	}

	/// Get the response status code and message.
	public func getStatus() -> (Int, String) {
		return self.connection.getStatus()
	}

	/// Adds the cookie object to the response
	public func addCookie(cookie cookie: Cookie) {
		self.cookiesArray.append(cookie)
	}

	public func appendBody(bytes b: [UInt8]) {
		self.bodyData.append(contentsOf: b)
	}

	public func appendBody(string s: String) {
		self.bodyData.append(contentsOf: [UInt8](s.utf8))
	}

	func respond(completion: () -> ()) {

		self.requestCompleted = { [weak self] in
			self?.sendResponse()
			completion()
		}

		doMainBody()
	}

	/// Perform a 302 redirect to the given url
	public func redirectTo(url: String) {
		self.setStatus(code: 302, message: "FOUND")
		self.replaceHeader(name: "Location", value: url)
	}

	/// Add an outgoing HTTP header
	public func addHeader(name n: String, value: String) {
		self.headersArray.append( (n, value) )
	}

	/// Set a HTTP header, replacing all existing instances of said header
	public func replaceHeader(name n: String, value: String) {
		for i in 0..<self.headersArray.count {
			if self.headersArray[i].0 == n {
				self.headersArray.remove(at: i)
			}
		}
		self.addHeader(name: n, value: value)
	}

	// directly called by the WebSockets impl
	func sendResponse() {
		for (key, value) in headersArray {
			connection.writeHeader(line: key + ": " + value)
		}
		// cookies
		if self.cookiesArray.count > 0 {
			let now = getNow()
			for cookie in self.cookiesArray {
				var cookieLine = "Set-Cookie: "
				cookieLine.append(cookie.name!.stringByEncodingURL)
				cookieLine.append("=")
				cookieLine.append(cookie.value!.stringByEncodingURL)
				if cookie.expiresIn != 0.0 {
					let formattedDate = try! formatDate(now + secondsToICUDate(Int(cookie.expiresIn)*60),
						format: "%a, %d-%b-%Y %T GMT", timezone: "GMT")
					cookieLine.append(";expires=" + formattedDate)
				}
				if let path = cookie.path {
					cookieLine.append("; path=" + path)
				}
				if let domain = cookie.domain {
					cookieLine.append("; domain=" + domain)
				}
				if let secure = cookie.secure {
					if secure == true {
						cookieLine.append("; secure")
					}
				}
				if let httpOnly = cookie.httpOnly {
					if httpOnly == true {
						cookieLine.append("; HttpOnly")
					}
				}
                // etc...
				connection.writeHeader(line: cookieLine)
			}
		}
		connection.writeHeader(line: "Content-Length: \(bodyData.count)")

		connection.writeBody(bytes: bodyData)
	}

	private func doMainBody() {

		do {

			return try include(path: request.pathInfo ?? "error", local: false)

		} catch PerfectError.FileError(let code, let msg) {

			print("File exception \(code) \(msg)")
			self.setStatus(code: code == 404 ? Int(code) : 500, message: msg)
			self.bodyData = [UInt8]("File exception \(code) \(msg)".utf8)

		} catch MustacheError.SyntaxError(let msg) {

			print("MustacheError.SyntaxError \(msg)")
			self.setStatus(code: 500, message: msg)
			self.bodyData = [UInt8]("Mustache syntax error \(msg)".utf8)

		} catch MustacheError.EvaluationError(let msg) {

			print("MustacheError.EvaluationError exception \(msg)")
			self.setStatus(code: 500, message: msg)
			self.bodyData = [UInt8]("Mustache evaluation error \(msg)".utf8)

		} catch let e {
			print("Unexpected exception \(e)")
		}
		self.requestCompleted()
	}

	func includeVirtual(path path: String) throws {
		Routing.handleRequest(self.request, response: self)
	}

	func include(path path: String, local: Bool) throws {
		return try self.includeVirtual(path: path)
	}

	private func makeNonRelative(path: String, local: Bool = false) -> String {
		if includeStack.count == 0 {
			return "/" + path
		}
		if local {
			return includeStack.last!.stringByDeletingLastPathComponent + "/" + path
		}
		return request.pathInfo!.stringByDeletingLastPathComponent + "/" + path
	}
}
