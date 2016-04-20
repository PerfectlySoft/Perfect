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
	
	public var requestCompletedCallback: () -> () = {}
	
	internal init(_ c: WebConnection, request: WebRequest) {
		self.connection = c
		self.request = request
	}
	
	/// Set the response status code and message. For example, 200, "OK".
	public func setStatus(code: Int, message: String) {
		self.connection.setStatus(code, msg: message)
	}
	
	/// Get the response status code and message.
	public func getStatus() -> (Int, String) {
		return self.connection.getStatus()
	}
	
	/// Adds the cookie object to the response
	public func addCookie(cookie: Cookie) {
		self.cookiesArray.append(cookie)
	}
	
	public func appendBodyBytes(bytes: [UInt8]) {
		self.bodyData.append(contentsOf: bytes)
	}
	
	public func appendBodyString(string: String) {
		self.bodyData.append(contentsOf: [UInt8](string.utf8))
	}
	
	func respond(completion: () -> ()) {
		
		self.requestCompletedCallback = { [weak self] in
			self?.sendResponse()
			completion()
		}
		
		doMainBody()
	}
	
	/// Perform a 302 redirect to the given url
	public func redirectTo(url: String) {
		self.setStatus(302, message: "FOUND")
		self.replaceHeader("Location", value: url)
	}
	
	/// Add an outgoing HTTP header
	public func addHeader(name: String, value: String) {
		self.headersArray.append( (name, value) )
	}
	
	/// Set a HTTP header, replacing all existing instances of said header
	public func replaceHeader(name: String, value: String) {
		for i in 0..<self.headersArray.count {
			if self.headersArray[i].0 == name {
				self.headersArray.remove(at: i)
			}
		}
		self.addHeader(name, value: value)
	}
	
	// directly called by the WebSockets impl
	func sendResponse() {
		for (key, value) in headersArray {
			connection.writeHeaderLine(key + ": " + value)
		}
		// cookies
		if self.cookiesArray.count > 0 {
			let standardDateFormat = "';expires='E, dd-LLL-yyyy HH:mm:ss 'GMT'"
			let now = getNow()
			for cookie in self.cookiesArray {
				var cookieLine = "Set-Cookie: "
				cookieLine.append(cookie.name!.stringByEncodingURL)
				cookieLine.append("=")
				cookieLine.append(cookie.value!.stringByEncodingURL)
				if cookie.expiresIn != 0.0 {
					let formattedDate = try! formatDate(now + secondsToICUDate(Int(cookie.expiresIn)*60),
						format: standardDateFormat, timezone: "GMT")
					cookieLine.append(formattedDate)
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
                connection.writeHeaderLine(cookieLine)
			}
		}
		connection.writeHeaderLine("Content-Length: \(bodyData.count)")
		
		connection.writeBodyBytes(bodyData)
	}
	
	private func doMainBody() {
		
		do {
		
			return try include(request.pathInfo ?? "error", local: false)
			
		} catch PerfectError.FileError(let code, let msg) {
			
			print("File exception \(code) \(msg)")
			self.setStatus(code == 404 ? Int(code) : 500, message: msg)
			self.bodyData = [UInt8]("File exception \(code) \(msg)".utf8)
			
		} catch MustacheError.SyntaxError(let msg) {
		
			print("MustacheError.SyntaxError \(msg)")
			self.setStatus(500, message: msg)
			self.bodyData = [UInt8]("Mustache syntax error \(msg)".utf8)
			
		} catch MustacheError.EvaluationError(let msg) {
			
			print("MustacheError.EvaluationError exception \(msg)")
			self.setStatus(500, message: msg)
			self.bodyData = [UInt8]("Mustache evaluation error \(msg)".utf8)
			
		} catch let e {
			print("Unexpected exception \(e)")
		}
		self.requestCompletedCallback()
	}
	
	func includeVirtual(path: String) throws {
		guard let handler = PageHandlerRegistry.getRequestHandler(self) else {
			throw PerfectError.FileError(404, "The path \(path) had no associated handler")
		}
		handler.handleRequest(self.request, response: self)
	}
	
	func include(path: String, local: Bool) throws {
		
		var fullPath = path
        if let decodedPath = path.stringByDecodingURL {
            fullPath = decodedPath
        }
		if !path.hasPrefix("/") {
			fullPath = makeNonRelative(path, local: local)
		}
		fullPath = request.documentRoot + fullPath
		
		let file = File(fullPath)
		
		if PageHandlerRegistry.hasGlobalHandler() && (!path.hasSuffix("."+mustacheExtension) || !file.exists()) {
			return try self.includeVirtual(path)
		}
		
		if !path.hasSuffix("."+mustacheExtension) {
			throw PerfectError.FileError(404, "The file \(path) was not a mustache template file")
		}
		
		do {
			guard file.exists() else {
				throw PerfectError.FileError(404, "Not Found")
			}
			
			try file.openRead()
			defer { file.close() }
			let bytes = try file.readSomeBytes(file.size())
			
			let parser = MustacheParser()
			let str = UTF8Encoding.encode(bytes)
			let template = try parser.parse(str)
			
			let context = MustacheEvaluationContext(webResponse: self)
			context.filePath = fullPath
			
			let collector = MustacheEvaluationOutputCollector()
			template.templateName = path

			try template.evaluatePragmas(context, collector: collector)
			template.evaluate(context, collector: collector)
			
			let fullString = collector.asString()
			self.bodyData += Array(fullString.utf8)
		}
		self.requestCompletedCallback()
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






