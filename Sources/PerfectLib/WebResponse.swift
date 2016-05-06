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

extension Cookie {
    func serialize(timeStamp: Double) -> String {
        var cookieLine = [String]()
        
        cookieLine.append("Set-Cookie: \(self.name!.stringByEncodingURL)=\(self.value!.stringByEncodingURL)")
        if self.expiresIn != 0.0 {
            let formattedDate = try! formatDate(timeStamp + secondsToICUDate(Int(self.expiresIn)*60),
                                                format: "%a, %d-%b-%Y %T GMT", timezone: "GMT")
            cookieLine.append("expires=\(formattedDate)")
        }
        if let path = self.path {
            cookieLine.append("path=\(path)")
        }
        if let domain = self.domain {
            cookieLine.append("domain=\(domain)")
        }
        if let secure = self.secure where secure == true {
            cookieLine.append("secure")
        }
        if let httpOnly = self.httpOnly where httpOnly == true {
            cookieLine.append("HttpOnly")
        }
        return cookieLine.joined(separator: ";")
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
        self.sendResponse(doMainBody())
	}


	// directly called by the WebSockets impl
    func sendResponse(response: Response) {
        
        for (key, value) in response.headers {
            connection.writeHeaderLine("\(key): \(value)")
        }
        
		// cookies
		if response.cookies.count > 0 {
			let now = getNow()
            
			for cookie in response.cookies {
                connection.writeHeaderLine(cookie.serialize(now))
			}
		}
		connection.writeHeaderLine("Content-Length: \(bodyData.count)")
        response.body.observe({ data in
                self.connection.writeBodyBytes(data)
            }, end: {
                self.connection.connection.close()
            })
	}

	private func doMainBody() -> Response {

		do {
			return try include(request.pathInfo ?? "error", local: false)

		} catch PerfectError.FileError(let code, let msg) {

			print("File exception \(code) \(msg)")
            return Response(statusCode: (Int(code), msg),
                body: "File exception \(code) \(msg)")
                

		} catch MustacheError.SyntaxError(let msg) {

			print("MustacheError.SyntaxError \(msg)")
            return .InternalError("Mustache syntax error \(msg)")

		} catch MustacheError.EvaluationError(let msg) {

			print("MustacheError.EvaluationError exception \(msg)")
            return .InternalError("Mustache evaluation error \(msg)")

		} catch let e {
			print("Unexpected exception \(e)")
            return .InternalError("Unexpected exception \(e)")
		}
        
	}

	func includeVirtual(path: String) throws -> Response {
		return Routing.handleRequest(self.request, response: self)
	}

	func include(path: String, local: Bool) throws -> Response {
		return try self.includeVirtual(path)
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
