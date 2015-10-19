//
//  WebResponse.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/6/15.
//
//

import Foundation

/// This class bundles together the values which will be used to set a cookie in the outgoing response
public class Cookie {
	var name: String?
	var value: String?
	var domain: String?
	var expires: String?
	var expiresIn: Double = 0.0 // seconds from now. may be negative. 0.0 means no expiry (session cookie)
	var path: String?
	var secure: Bool?
	var httpOnly: Bool?
}

/// Represents an outgoing web response. Handles the following tasks:
/// - Management of sessions
/// - Collecting HTTP response headers & cookies.
/// - Locating the response template file, parsing it, evaluating it and returning the resulting data.
/// - Provides access to the WebRequest object.
public class WebResponse {
	
	var connection: WebConnection
	public var request: WebRequest
	
	public var outputEncoding = "UTF-8"
	
	var headersArray = [(String, String)]()
	var cookiesArray = [Cookie]()
	var includeStack = [String]()
	
	var appStatus = 0
	var appMessage = ""
	
	var bodyData = [UInt8]()
	
	var sessions = Dictionary<String, SessionManager>()
	
	internal init(_ c: WebConnection, request: WebRequest) {
		self.connection = c
		self.request = request
	}
	
	public func setStatus(code: Int, message: String) {
		self.connection.setStatus(code, msg: message)
	}
	
	public func getStatus() -> (Int, String) {
		return self.connection.getStatus()
	}
	
	/// Adds the cookie object to the response
	public func addCookie(cookie: Cookie) {
		self.cookiesArray.append(cookie)
	}
	
	func respond() {
		doMainBody()
		doSessionHeaders()
		sendResponse()
		commitSessions()
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
		let s = SessionManager(SessionConfiguration(named, id: getSessionKey(SESSION_NAME_PREFIX + named)))
		self.sessions[named] = s
		return s
	}
	
	/// Provides access to the indicated `SessionManager` object using the given `SessionConfiguration` data.
	/// - throws: If the session already exists, `LassoError.APIError` is thrown.
	public func getSession(named: String, withConfiguration: SessionConfiguration) throws -> SessionManager {
		guard self.sessions[named] == nil else {
			throw LassoError.APIError("WebResponse getSession withConfiguration: session was already initialized")
		}
		let s = SessionManager(SessionConfiguration(named, id: getSessionKey(SESSION_NAME_PREFIX + named), copyFrom: withConfiguration))
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
		for var i = 0; i < self.headersArray.count; ++i {
			if self.headersArray[i].0 == name {
				self.headersArray.removeAtIndex(i)
			}
		}
		self.addHeader(name, value: value)
	}
	
	private func sendResponse() {
		for (key, value) in headersArray {
			connection.writeHeaderLine(key + ": " + value)
		}
		// cookies
		if self.cookiesArray.count > 0 {
			let standardDateFormat = "';expires='E, dd-LLL-yyyy HH:mm:ss 'GMT'"
			let now = ICU.getNow()
			for cookie in self.cookiesArray {
				var cookieLine = "Set-Cookie: "
				cookieLine.appendContentsOf(cookie.name!.stringByAddingPercentEncodingWithAllowedCharacters(NSCharacterSet.URLQueryAllowedCharacterSet())!)
				cookieLine.appendContentsOf("=")
				cookieLine.appendContentsOf(cookie.value!.stringByAddingPercentEncodingWithAllowedCharacters(NSCharacterSet.URLQueryAllowedCharacterSet())!)
				if cookie.expiresIn != 0.0 {
					let formattedDate = try! ICU.formatDate(now + ICU.secondsToICUDate(Int(cookie.expiresIn)*60),
						format: standardDateFormat, timezone: "GMT")
					cookieLine.appendContentsOf(formattedDate)
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
		
			try include(request.pathInfo())
			
		} catch LassoError.FileError(let code, let msg) {
			
			print("File exception \(code) \(msg)")
			self.setStatus(code == 404 ? Int(code) : 500, message: msg)
			self.bodyData = [UInt8]("File exception \(code) \(msg)".utf8)
			
		} catch MoustacheError.SyntaxError(let msg) {
		
			print("MoustacheError.SyntaxError \(msg)")
			self.setStatus(500, message: msg)
			self.bodyData = [UInt8]("Moustache syntax error \(msg)".utf8)
			
		} catch MoustacheError.EvaluationError(let msg) {
			
			print("MoustacheError.EvaluationError exception \(msg)")
			self.setStatus(500, message: msg)
			self.bodyData = [UInt8]("Moustache evaluation error \(msg)".utf8)
			
		} catch let e {
			print("Unexpected exception \(e)")
		}
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
	
	func include(path: String, local: Bool = false) throws {
		
		if !path.hasSuffix("."+MOUSTACHE_EXTENSION) {
			throw LassoError.FileError(404, "The file \(path) was not a moustache template file")
		}
		
		var fullPath = path
		if !path.hasPrefix("/") {
			fullPath = makeNonRelative(path, local: local)
		}
		fullPath = request.documentRoot + fullPath
		
		do {
			let file = File(fullPath)
			guard file.exists() else {
				throw LassoError.FileError(404, "Not Found")
			}
			
			try file.openRead()
			defer { file.close() }
			let bytes = try file.readSomeBytes(file.size())
			
			// !FIX! cache parsed moustache files
			// check mod dates for recompilation
			
			let parser = MoustacheParser()
			let str = UTF8Encoding.encode(bytes)
			let template = try parser.parse(str)
			
			let context = MoustacheEvaluationContext(webResponse: self)
			context.filePath = fullPath
			
			let collector = MoustacheEvaluationOutputCollector()
			template.templateName = path

			try template.evaluatePragmas(context, collector: collector)
			template.evaluate(context, collector: collector)
			
			let fullString = collector.asString()
//			print(fullString)
			self.bodyData += Array(fullString.utf8)
		}
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
}






