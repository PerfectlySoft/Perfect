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
/*
class MustacheCacheItem {
	let modificationDate: Int
	let template: MustacheTemplate
	
	init(modificationDate: Int, template: MustacheTemplate) {
		self.modificationDate = modificationDate
		self.template = template
	}
}

let mustacheTemplateCache = RWLockCache<String, MustacheCacheItem>()
*/
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
	
	var sessions = Dictionary<String, SessionManager>()
	
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
		self.bodyData.appendContentsOf(bytes)
	}
	
	public func appendBodyString(string: String) {
		self.bodyData.appendContentsOf([UInt8](string.utf8))
	}
	
	func respond(completion: () -> ()) {
		
		self.requestCompletedCallback = { [weak self] in
			
			self?.doSessionHeaders()
			self?.sendResponse()
			self?.commitSessions()
			
			completion()
		}
		
		doMainBody()
	}
	
	/// !FIX! needs to pull key from possible request param
	func getSessionKey(name: String) -> String {
		// ...
		for (cName, cValue) in self.request.cookies {
			if name == cName {
				return cValue
			}
		}
		return SessionManager.generateSessionKey()
	}
	
	/// Provides access to the indicated `SessionManager` object.
	/// If the session does not exist it is created. If it does exist, the existing object is returned.
	public func getSession(named: String) -> SessionManager {
		if let s = self.sessions[named] {
			return s
		}
		let s = SessionManager(SessionConfiguration(named, id: getSessionKey(perfectSessionNamePrefix + named)))
		self.sessions[named] = s
		return s
	}
	
	/// Provides access to the indicated `SessionManager` object using the given `SessionConfiguration` data.
	/// - throws: If the session already exists, `PerfectError.APIError` is thrown.
	public func getSession(named: String, withConfiguration: SessionConfiguration) throws -> SessionManager {
		guard self.sessions[named] == nil else {
			throw PerfectError.APIError("WebResponse getSession withConfiguration: session was already initialized")
		}
		let s = SessionManager(SessionConfiguration(named, id: getSessionKey(perfectSessionNamePrefix + named), copyFrom: withConfiguration))
		self.sessions[named] = s
		return s
	}
	
	/// Discards a previously started session. The session will not be propagated and any changes to the session's variables will be discarded.
	public func abandonSession(named: String) {
		self.sessions.removeValueForKey(named)
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
				self.headersArray.removeAtIndex(i)
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
			let now = ICU.getNow()
			for cookie in self.cookiesArray {
				var cookieLine = "Set-Cookie: "
				cookieLine.appendContentsOf(cookie.name!.stringByEncodingURL)
				cookieLine.appendContentsOf("=")
				cookieLine.appendContentsOf(cookie.value!.stringByEncodingURL)
				if cookie.expiresIn != 0.0 {
					let formattedDate = try! ICU.formatDate(now + ICU.secondsToICUDate(Int(cookie.expiresIn)*60),
						format: standardDateFormat, timezone: "GMT")
					cookieLine.appendContentsOf(formattedDate)
				}
				if let path = cookie.path {
					cookieLine.appendContentsOf("; path=" + path)
				}
				if let domain = cookie.domain {
					cookieLine.appendContentsOf("; domain=" + domain)
				}
				if let secure = cookie.secure {
					if secure == true {
						cookieLine.appendContentsOf("; secure")
					}
				}
				if let httpOnly = cookie.httpOnly {
					if httpOnly == true {
						cookieLine.appendContentsOf("; HttpOnly")
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
		
			return try include(request.pathInfo(), local: false)
			
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
	
	func doSessionHeaders() {
		for (_, session) in self.sessions {
			session.initializeForResponse(self)
		}
	}
	
	func commitSessions() {
		for (name, session) in self.sessions {
			do {
				try session.commit()
			} catch let e {
				LogManager.logMessage("Exception while committing session \(name) \(e)")
			}
		}
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
		return request.pathInfo().stringByDeletingLastPathComponent + "/" + path
	}
	
	
	// WARNING NOTE Using the RWLockCache, even just for read access seems to bring out some sort of bug in the
	// ARC system. Therefore, this function is not currently called.
	// !FIX! track this problem down
	/*
	func includeCached(path: String, local: Bool = false) throws {
	
	if !path.hasSuffix("."+mustacheExtension) {
	throw PerfectError.FileError(404, "The file \(path) was not a mustache template file")
	}
	
	var fullPath = path
	if !path.hasPrefix("/") {
	fullPath = makeNonRelative(path, local: local)
	}
	fullPath = request.documentRoot + fullPath
	
	do {
	let file = File(fullPath)
	guard file.exists() else {
	throw PerfectError.FileError(404, "Not Found")
	}
	let diskModTime = file.modificationTime()
	var cacheItem = mustacheTemplateCache.valueForKey(fullPath)//, validatorCallback: { (value) -> Bool in
	//				return diskModTime == value.modificationDate
	//			})
	
	if cacheItem == nil {
	print("REPLACING")
	try file.openRead()
	defer { file.close() }
	let bytes = try file.readSomeBytes(file.size())
	
	let parser = MustacheParser()
	let str = UTF8Encoding.encode(bytes)
	let template = try parser.parse(str)
	cacheItem = MustacheCacheItem(modificationDate: diskModTime, template: template)
	mustacheTemplateCache.setValueForKey(fullPath, value: cacheItem!)
	}
	
	let template = cacheItem!.template
	let context = MustacheEvaluationContext(webResponse: self)
	context.filePath = fullPath
	
	let collector = MustacheEvaluationOutputCollector()
	template.templateName = path
	
	try template.evaluatePragmas(context, collector: collector)
	template.evaluate(context, collector: collector)
	
	let fullString = collector.asString()
	self.bodyData += Array(fullString.utf8)
	}
	}
	*/
	
}






