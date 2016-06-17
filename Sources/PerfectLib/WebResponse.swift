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

import PerfectThread

/// This class bundles together the values which will be used to set a cookie in the outgoing response
public struct Cookie {
    /// Cookie expiration type
    public enum Expiration {
        /// Session cookie with no explicit expiration
        case session
        /// Expiratiuon in a number of seconds from now
        case relativeSeconds(Int)
        /// Expiration at an absolute time given in seconds from epoch
        case absoluteSeconds(Int)
        /// Custom expiration date string
        case absoluteDate(String)
    }
    
    /// Cookie name
	public let name: String?
    /// Cookie value
	public let value: String?
    /// Cookie domain
	public let domain: String?
    /// Cookie expiration
	public let expires: Expiration?
    /// Cookie path
	public let path: String?
    /// Cookie secure flag
	public let secure: Bool?
    /// Cookie http only flag
	public let httpOnly: Bool?

    /// Cookie public initializer
	public init(name: String?,
		value: String?,
		domain: String?,
		expires: Expiration?,
		path: String?,
		secure: Bool?,
		httpOnly: Bool?) {
			self.name = name
			self.value = value
			self.domain = domain
			self.expires = expires
			self.path = path
			self.secure = secure
			self.httpOnly = httpOnly
	}
}

/// Represents an outgoing web response. Handles the following tasks:
///
/// * Collecting HTTP response headers & cookies.
/// * Locating the response template file, parsing it, evaluating it and returning the resulting data.
/// * Provides access to the WebRequest object.
public class WebResponse {

	var connection: WebConnection

	/// The WebRequest for this response
	public var request: WebRequest

	var headersArray = [(String, String)]()
	var cookiesArray = [Cookie]()
	var includeStack = [String]()

	var appStatus = 0
	var appMessage = ""

	var bodyData = [UInt8]()
	
	var chunkedStarted = false
	var wroteHeaders = false
	
    /// Called by handlers to complete the current request.
	public var requestCompleted: () -> () = {}

	init(_ c: WebConnection, request: WebRequest) {
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

	/// Adds the cookie object to the response.
	public func addCookie(cookie cooky: Cookie) {
		self.cookiesArray.append(cooky)
	}

	/// Appends the given bytes to the outgoing content body.
	public func appendBody(bytes b: [UInt8]) {
		self.bodyData.append(contentsOf: b)
	}
	
	/// Appends the given string to the outgoing content body.
	/// String is converted to UTF8 bytes.
	public func appendBody(string s: String) {
		self.bodyData.append(contentsOf: [UInt8](s.utf8))
	}

	/// Pushes any waiting body data to the client.
	/// Calls the given completion handler when done.
	/// The parameter to the handler will be true if the data was successfully pushed. If false is given then the request should be considered to have been aborted.
	public func pushBody(completion: (Bool) -> ()) {
		self.writeHeaders()
		self.connection.writeBody(bytes: self.bodyData) {
			ok in
			
			self.bodyData.removeAll()
			
			Threading.dispatch {
				completion(ok)
			}
		}
	}
	
	/// If HTTP chunked transfer encoding has not already been started, chunked starts and the existing HTTP headers are written.
	/// Any existing body data is sent to the client as a chunk and the body data is cleared for the next round of appendBody/appendBytes.
	/// Calls the given completion handler when done. 
	/// The parameter to the handler will be true if the data was successfully pushed. If false is given then the request should be considered to have been aborted.
	public func pushChunked(completion: (Bool) -> ()) {
		if !self.chunkedStarted {
			self.chunkedStarted = true
			
			self.replaceHeader(name: "Transfer-Encoding", value: "chunked")
			self.writeHeaders()
		}
		let bodyCount = self.bodyData.count
		if bodyCount > 0 {
			let hexString = "\(String(bodyCount, radix: 16, uppercase: true))\r\n"
			connection.writeBody(bytes: Array(hexString.utf8)) {
				ok in
				
				guard ok else {
					return completion(false)
				}
				
				self.bodyData.append(httpCR)
				self.bodyData.append(httpLF)
				self.connection.writeBody(bytes: self.bodyData) {
					ok in
					
					self.bodyData.removeAll()
					
					Threading.dispatch {
						completion(ok)
					}
				}
			}
		} else {
			completion(true)
		}
	}
	
	func respond(completion: () -> ()) {

		self.requestCompleted = { [weak self] in
			
			guard let `self` = self else {
				return completion()
			}
			
			if self.chunkedStarted {
				// write any remaining body data
				// write the final 0 chunk
				self.pushChunked {
					ok in
					
					guard ok else {
						return completion()
					}
					
					self.appendBody(string: "0\r\n\r\n")
					self.writeBody {
						_ in
						
						completion()
					}
				}
			} else {
				self.writeHeaders()
				self.writeBody {
					_ in
				
					completion()
				}
			}
		}

		Routing.handleRequest(self.request, response: self)
	}

	/// Perform a 302 redirect to the given url.
	public func redirectTo(url: String) {
		self.setStatus(code: 302, message: "FOUND")
		self.replaceHeader(name: "Location", value: url)
	}

	/// Add an outgoing HTTP header.
	public func addHeader(name n: String, value: String) {
		self.headersArray.append( (n, value) )
	}

	/// Set a HTTP header, replacing all existing instances of said header.
	public func replaceHeader(name n: String, value: String) {
		for i in 0..<self.headersArray.count {
			if self.headersArray[i].0 == n {
				self.headersArray.remove(at: i)
			}
		}
		self.addHeader(name: n, value: value)
	}

	// queues headers to be written with the first body chunk.
	func writeHeaders() {
		
		guard !wroteHeaders else {
			return
		}
		
		wroteHeaders = true
		
		var foundContentLength = false
		for (key, value) in headersArray {
			connection.writeHeader(line: key + ": " + value)
			if !foundContentLength && key.lowercased() == "content-length" {
				foundContentLength = true
			}
		}
		
		// if this is not a chunked request and there is not already an existing Content-Length header, add it
		if !self.chunkedStarted && !foundContentLength {
			connection.writeHeader(line: "Content-Length: \(bodyData.count)")
		}		
		
		// cookies
		if self.cookiesArray.count > 0 {
			let now = getNow()
			for cookie in self.cookiesArray {
				var cookieLine = "Set-Cookie: "
				cookieLine.append(cookie.name!.stringByEncodingURL)
				cookieLine.append("=")
				cookieLine.append(cookie.value!.stringByEncodingURL)
                
                if let expires = cookie.expires {
                    switch expires {
                    case .session: ()
                    case .absoluteDate(let date):
                        cookieLine.append(";expires=" + date)
                    case .absoluteSeconds(let seconds):
                        let formattedDate = try! formatDate(secondsToICUDate(seconds*60),
                                                            format: "%a, %d-%b-%Y %T GMT",
                                                            timezone: "GMT")
                        cookieLine.append(";expires=" + formattedDate)
                    case .relativeSeconds(let seconds):
                        let formattedDate = try! formatDate(now + secondsToICUDate(seconds*60),
                                                            format: "%a, %d-%b-%Y %T GMT",
                                                            timezone: "GMT")
                        cookieLine.append(";expires=" + formattedDate)
                    }
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
	}
	
	func writeBody(completion: (Bool) -> ()) {
		connection.writeBody(bytes: bodyData) {
			ok in
			self.bodyData.removeAll()
			completion(ok)
		}
	}
}
