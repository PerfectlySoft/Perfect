//
//  HTTPResponse.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2016-06-20.
//	Copyright (C) 2016 PerfectlySoft, Inc.
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

/// HTTP response status code/msg.
public enum HTTPResponseStatus: CustomStringConvertible {
    case `continue`
    case switchingProtocols
    case ok
    case created
    case accepted
    case nonAuthoritativeInformation
    case noContent
    case resetContent
    case partialContent
    case multipleChoices
    case movedPermanently
    case found
    case seeOther
    case notModified
    case useProxy
    case temporaryRedirect
    case badRequest
    case unauthorized
    case paymentRequired
    case forbidden
    case notFound
    case methodNotAllowed
    case notAcceptable
    case proxyAuthenticationRequired
    case requestTimeout
    case conflict
    case gone
    case lengthRequired
    case preconditionFailed
    case requestEntityTooLarge
    case requestURITooLong
    case unsupportedMediaType
    case requestedRangeNotSatisfiable
    case expectationFailed
    case internalServerError
    case notImplemented
    case badGateway
    case serviceUnavailable
    case gatewayTimeout
    case httpVersionNotSupported
    case custom(code: Int, message: String)
    /// Returna the textual code and message pair.
    public var description: String {
        switch self {
        case .continue              : return "100 Continue"
        case .switchingProtocols	: return "101 Switching Protocols"
        case .ok					: return "200 OK"
        case .created               : return "201 Created"
        case .accepted              : return "202 Accepted"
        case .nonAuthoritativeInformation	: return "203 Non-Authoritative Information"
        case .noContent             : return "204 No Content"
        case .resetContent          : return "205 Reset Content"
        case .partialContent		: return "206 Partial Content"
        case .multipleChoices       : return "300 Multiple Choices"
        case .movedPermanently      : return "301 Moved Permanently"
        case .found                 : return "302 Found"
        case .seeOther              : return "303 See Other"
        case .notModified           : return "304 Not Modified"
        case .useProxy              : return "305 Use Proxy"
        case .temporaryRedirect     : return "307 Temporary Redirect"
        case .badRequest			: return "400 Bad Request"
        case .unauthorized          : return "401 Unauthorized"
        case .paymentRequired       : return "402 Payment Required"
        case .forbidden             : return "403 Forbidden"
        case .notFound              : return "404 Not Found"
        case .methodNotAllowed      : return "405 Method Not Allowed"
        case .notAcceptable         : return "406 Not Acceptable"
        case .proxyAuthenticationRequired	: return "407 Proxy Authentication Required"
        case .requestTimeout		: return "408 Request Timeout"
        case .conflict              : return "409 Conflict"
        case .gone                  : return "410 Gone"
        case .lengthRequired		: return "411 Length Required"
        case .preconditionFailed	: return "412 Precondition Failed"
        case .requestEntityTooLarge	: return "413 Request Entity Too Large"
        case .requestURITooLong	: return "414 Request-URI Too Long"
        case .unsupportedMediaType	: return "415 Unsupported Media Type"
        case .requestedRangeNotSatisfiable	: return "416 Requested Range Not Satisfiable"
        case .expectationFailed	: return "417 Expectation Failed"
        case .internalServerError	: return "500 Internal Server Error"
        case .notImplemented		: return "501 Not Implemented"
        case .badGateway			: return "502 Bad Gateway"
        case .serviceUnavailable	: return "503 Service Unavailable"
        case .gatewayTimeout		: return "504 Gateway Timeout"
        case .httpVersionNotSupported	: return "505 HTTP Version Not Supported"
        case .custom(let code, let message): return "\(code) \(message)"
        }
    }
    
    static func statusFrom(code: Int) -> HTTPResponseStatus {
        switch code {
        case 100: return .continue
        case 101: return .switchingProtocols
        case 200: return .ok
        case 201: return .created
        case 202: return .accepted
        case 203: return .nonAuthoritativeInformation
        case 204: return .noContent
        case 205: return .resetContent
        case 206: return .partialContent
        case 300: return .multipleChoices
        case 301: return .movedPermanently
        case 302: return .found
        case 303: return .seeOther
        case 304: return .notModified
        case 305: return .useProxy
        case 307: return .temporaryRedirect
        case 400: return .badRequest
        case 401: return .unauthorized
        case 402: return .paymentRequired
        case 403: return .forbidden
        case 404: return .notFound
        case 405: return .methodNotAllowed
        case 406: return .notAcceptable
        case 407: return .proxyAuthenticationRequired
        case 408: return .requestTimeout
        case 409: return .conflict
        case 410: return .gone
        case 411: return .lengthRequired
        case 412: return .preconditionFailed
        case 413: return .requestEntityTooLarge
        case 414: return .requestURITooLong
        case 415: return .unsupportedMediaType
        case 416: return .requestedRangeNotSatisfiable
        case 417: return .expectationFailed
        case 500: return .internalServerError
        case 501: return .notImplemented
        case 502: return .badGateway
        case 503: return .serviceUnavailable
        case 504: return .gatewayTimeout
        case 505: return .httpVersionNotSupported
        default:
            return .custom(code: code, message: "Custom")
        }
    }
	
	/// The numeric code for this response status.
    public var code: Int {
        switch self {
        case .continue: return 100
        case .switchingProtocols: return 101
        case .ok: return 200
        case .created: return 201
        case .accepted: return 202
        case .nonAuthoritativeInformation: return 203
        case .noContent: return 204
        case .resetContent: return 205
        case .partialContent: return 206
        case .multipleChoices: return 300
        case .movedPermanently: return 301
        case .found: return 302
        case .seeOther: return 303
        case .notModified: return 304
        case .useProxy: return 305
        case .temporaryRedirect: return 307
        case .badRequest: return 400
        case .unauthorized: return 401
        case .paymentRequired: return 402
        case .forbidden: return 403
        case .notFound: return 404
        case .methodNotAllowed: return 405
        case .notAcceptable: return 406
        case .proxyAuthenticationRequired: return 407
        case .requestTimeout: return 408
        case .conflict: return 409
        case .gone: return 410
        case .lengthRequired: return 411
        case .preconditionFailed: return 412
        case .requestEntityTooLarge: return 413
        case .requestURITooLong: return 414
        case .unsupportedMediaType: return 415
        case .requestedRangeNotSatisfiable: return 416
        case .expectationFailed: return 417
        case .internalServerError: return 500
        case .notImplemented: return 501
        case .badGateway: return 502
        case .serviceUnavailable: return 503
        case .gatewayTimeout: return 504
        case .httpVersionNotSupported: return 505
        case .custom(let code, _): return code
        }
    }
}

/// This bundles together the values which will be used to set a cookie in the outgoing response
public struct HTTPCookie {
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

/// An HTTP based response object.
/// Contains all header and body data which will be delivered to the client.
public protocol HTTPResponse: class {
	/// The request object which instigated this response.
    var request: HTTPRequest { get }
	/// The HTTP response status.
    var status: HTTPResponseStatus { get set }
	/// Indicate that the response should attempt to stream all outgoing data.
	/// This is primarily used when the resulting content length can not be known.
    var isStreaming: Bool { get set }
	/// Body data waiting to be sent to the client.
	/// This will be emptied after each chunk is sent.
    var bodyBytes: [UInt8] { get set }
    /// Returns the requested outgoing header value.
    func header(_ named: HTTPResponseHeader.Name) -> String?
	/// Add a header to the outgoing response.
	/// No check for duplicate or repeated headers will be made.
    func addHeader(_ named: HTTPResponseHeader.Name, value: String)
	/// Set the indicated header value. 
	/// If the header already exists then the existing value will be replaced.
    func setHeader(_ named: HTTPResponseHeader.Name, value: String)
    /// Provide access to all current header values.
    var headers: AnyIterator<(HTTPResponseHeader.Name, String)> { get }
    /// Add a cookie to the outgoing response.
    func addCookie(_: HTTPCookie)
    /// Append data to the bodyBytes member.
    func appendBody(bytes: [UInt8])
	/// Append String data to the outgoing response.
	/// All such data will be converted to a UTF-8 encoded [UInt8]
    func appendBody(string: String)
	/// Encodes the Dictionary as a JSON string and converts that to a UTF-8 encoded [UInt8]
    func setBody(json: [String:Any]) throws
	/// Push all currently available headers and body data to the client.
	/// May be called multiple times.
    func push(callback: (Bool) -> ())
	/// Indicate that the request has completed.
	/// Any currently available headers and body data will be pushed to the client.
	/// No further request related activities should be performed after calling this.
    func completed()
}
