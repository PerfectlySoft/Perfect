//
//  HTTPHeaders.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2016-06-17.
//    Copyright (C) 2016 PerfectlySoft, Inc.
//
// ===----------------------------------------------------------------------===//
//
// This source file is part of the Perfect.org open source project
//
// Copyright (c) 2015 - 2016 PerfectlySoft Inc. and the Perfect project authors
// Licensed under Apache License v2.0
//
// See http://perfect.org/licensing.html for license information
//
// ===----------------------------------------------------------------------===//
//

/// An HTTP request header.
public enum HTTPRequestHeader {
	/// A header name type. Each has a corresponding value type.
	public enum Name: Hashable {
		case accept, acceptCharset, acceptEncoding, acceptLanguage, acceptDatetime, authorization
		case cacheControl, connection, cookie, contentLength, contentMD5, contentType
		case date, expect, forwarded, from, host
		case ifMatch, ifModifiedSince, ifNoneMatch, ifRange, ifUnmodifiedSince
		case maxForwards, origin, pragma, proxyAuthorization, range, referer
		case te, userAgent, upgrade, via, warning, xRequestedWith, xRequestedBy, dnt
		case xAuthorization, xForwardedFor, xForwardedHost, xForwardedProto
		case frontEndHttps, xHttpMethodOverride, xATTDeviceId, xWapProfile
		case proxyConnection, xUIDH, xCsrfToken, accessControlRequestMethod, accessControlRequestHeaders
		case xB3TraceId, xB3SpanId, xB3ParentSpanId
		case custom(name: String)

        public func hash(into hasher: inout Hasher) {
            hasher.combine(standardName.lowercased())
        }

		public var standardName: String {
			switch self {
			case .accept: return "Accept"
			case .acceptCharset: return "Accept-Charset"
			case .acceptEncoding: return "Accept-Encoding"
			case .acceptLanguage: return "Accept-Language"
			case .acceptDatetime: return "Accept-Datetime"
			case .accessControlRequestMethod: return "Access-Control-Request-Method"
			case .accessControlRequestHeaders: return "Access-Control-Request-Headers"
			case .authorization: return "Authorization"
			case .cacheControl: return "Cache-Control"
			case .connection: return "Connection"
			case .cookie: return "Cookie"
			case .contentLength: return "Content-Length"
			case .contentMD5: return "Content-MD5"
			case .contentType: return "Content-Type"
			case .date: return "Date"
			case .expect: return "Expect"
			case .forwarded: return "Forwarded"
			case .from: return "From"
			case .host: return "Host"
			case .ifMatch: return "If-Match"
			case .ifModifiedSince: return "If-Modified-Since"
			case .ifNoneMatch: return "If-None-Match"
			case .ifRange: return "If-Range"
			case .ifUnmodifiedSince: return "If-Unmodified-Since"
			case .maxForwards: return "Max-Forwards"
			case .origin: return "Origin"
			case .pragma: return "Pragma"
			case .proxyAuthorization: return "Proxy-Authorization"
			case .range: return "Range"
			case .referer: return "Referer"
			case .te: return "TE"
			case .userAgent: return "User-Agent"
			case .upgrade: return "Upgrade"
			case .via: return "Via"
			case .warning: return "Warning"
			case .xAuthorization: return "X-Authorization"
			case .xRequestedWith: return "X-Requested-with"
			case .xRequestedBy: return "X-Requested-by"
			case .dnt: return "DNT"
			case .xForwardedFor: return "X-Forwarded-For"
			case .xForwardedHost: return "X-Forwarded-Host"
			case .xForwardedProto: return "X-Forwarded-Proto"
			case .frontEndHttps: return "Front-End-Https"
			case .xHttpMethodOverride: return "X-HTTP-Method-Override"
			case .xATTDeviceId: return "X-Att-Deviceid"
			case .xWapProfile: return "X-WAP-Profile"
			case .proxyConnection: return "Proxy-Connection"
			case .xUIDH: return "X-UIDH"
			case .xCsrfToken: return "X-CSRF-Token"
			case .xB3TraceId: return "X-B3-TraceId"
			case .xB3SpanId: return "X-B3-SpanId"
			case .xB3ParentSpanId: return "X-B3-ParentSpanId"
			case .custom(let str): return str
			}
		}

		static let lookupTable: [String: HTTPRequestHeader.Name] = [
			"accept": .accept,
			"accept-charset": .acceptCharset,
			"accept-encoding": .acceptEncoding,
			"accept-language": .acceptLanguage,
			"accept-datetime": .acceptDatetime,
			"access-control-request-method": .accessControlRequestMethod,
			"access-control-request-headers": .accessControlRequestHeaders,
			"authorization": .authorization,
			"cache-control": .cacheControl,
			"connection": .connection,
			"cookie": .cookie,
			"content-length": .contentLength,
			"content-md5": .contentMD5,
			"content-type": .contentType,
			"date": .date,
			"expect": .expect,
			"forwarded": .forwarded,
			"from": .from,
			"host": .host,
			"if-match": .ifMatch,
			"if-modified-since": .ifModifiedSince,
			"if-none-match": .ifNoneMatch,
			"if-range": .ifRange,
			"if-unmodified-since": .ifUnmodifiedSince,
			"max-forwards": .maxForwards,
			"origin": .origin,
			"pragma": .pragma,
			"proxy-authorization": .proxyAuthorization,
			"range": .range,
			"referer": .referer,
			"te": .te,
			"user-agent": .userAgent,
			"upgrade": .upgrade,
			"via": .via,
			"warning": .warning,
			"x-requested-with": .xRequestedWith,
			"x-requested-by": .xRequestedBy,
			"dnt": .dnt,
			"x-authorization": .xAuthorization,
			"x-forwarded-for": .xForwardedFor,
			"x-forwarded-host": .xForwardedHost,
			"x-forwarded-proto": .xForwardedProto,
			"front-end-https": .frontEndHttps,
			"x-http-method-override": .xHttpMethodOverride,
			"x-att-deviceid": .xATTDeviceId,
			"x-wap-profile": .xWapProfile,
			"proxy-connection": .proxyConnection,
			"x-uidh": .xUIDH,
			"x-csrf-token": .xCsrfToken,
			"x-b3-traceid": .xB3TraceId,
			"x-b3-spanid": .xB3SpanId,
			"x-b3-parentspanid": .xB3ParentSpanId
		]

		public static func fromStandard(name: String) -> HTTPRequestHeader.Name {
			if let found = HTTPRequestHeader.Name.lookupTable[name.lowercased()] {
				return found
			}
			return .custom(name: name)
		}
	}
}

public func == (lhs: HTTPRequestHeader.Name, rhs: HTTPRequestHeader.Name) -> Bool {
	return lhs.standardName.lowercased() == rhs.standardName.lowercased()
}

/// A HTTP response header.
public enum HTTPResponseHeader {

	public enum Name: Hashable {
		case accessControlAllowOrigin
		case accessControlAllowMethods
		case accessControlAllowCredentials
		case accessControlAllowHeaders
		case accessControlMaxAge
		case acceptPatch
		case acceptRanges
		case age
		case allow
		case altSvc
		case cacheControl
		case connection
		case contentDisposition
		case contentEncoding
		case contentLanguage
		case contentLength
		case contentLocation
		case contentMD5
		case contentRange
		case contentType
		case date
		case eTag
		case expires
		case lastModified
		case link
		case location
		case p3p
		case pragma
		case proxyAuthenticate
		case publicKeyPins
		case refresh
		case retryAfter
		case server
		case setCookie
		case status
		case strictTransportSecurity
		case trailer
		case transferEncoding
		case tsv
		case upgrade
		case vary
		case via
		case warning
		case wwwAuthenticate
		case xFrameOptions
		case xxsSProtection
		case contentSecurityPolicy
		case xContentSecurityPolicy
		case xWebKitCSP
		case xContentTypeOptions
		case xPoweredBy
		case xUACompatible
		case xContentDuration
		case upgradeInsecureRequests
		case xRequestID
		case xCorrelationID
		case xB3TraceId
		case xB3SpanId
		case xB3ParentSpanId
		case custom(name: String)

        public func hash(into hasher: inout Hasher) {
            hasher.combine(standardName.lowercased())
        }

		public var standardName: String {
			switch self {
			case .accessControlAllowOrigin: return "Access-Control-Allow-Origin"
			case .accessControlAllowMethods: return "Access-Control-Allow-Methods"
			case .accessControlAllowCredentials: return "Access-Control-Allow-Credentials"
			case .accessControlAllowHeaders: return "Access-Control-Allow-Headers"
			case .accessControlMaxAge: return "Access-Control-Max-Age"
			case .acceptPatch: return "Accept-Patch"
			case .acceptRanges: return "Accept-Ranges"
			case .age: return "Age"
			case .allow: return "Allow"
			case .altSvc: return "Alt-Svc"
			case .cacheControl: return "Cache-Control"
			case .connection: return "Connection"
			case .contentDisposition: return "Content-Disposition"
			case .contentEncoding: return "Content-Encoding"
			case .contentLanguage: return "Content-Language"
			case .contentLength: return "Content-Length"
			case .contentLocation: return "Content-Location"
			case .contentMD5: return "Content-MD5"
			case .contentRange: return "Content-Range"
			case .contentType: return "Content-Type"
			case .date: return "Date"
			case .eTag: return "ETag"
			case .expires: return "Expires"
			case .lastModified: return "Last-Modified"
			case .link: return "Link"
			case .location: return "Location"
			case .p3p: return "P3P"
			case .pragma: return "Pragma"
			case .proxyAuthenticate: return "Proxy-Authenticate"
			case .publicKeyPins: return "Public-Key-Pins"
			case .refresh: return "Refresh"
			case .retryAfter: return "Retry-After"
			case .server: return "Server"
			case .setCookie: return "Set-Cookie"
			case .status: return "Status"
			case .strictTransportSecurity: return "Strict-Transport-Security"
			case .trailer: return "Trailer"
			case .transferEncoding: return "Transfer-Encoding"
			case .tsv: return "TSV"
			case .upgrade: return "Upgrade"
			case .vary: return "Vary"
			case .via: return "Via"
			case .warning: return "Warning"
			case .wwwAuthenticate: return "WWW-Authenticate"
			case .xFrameOptions: return "X-Frame-Options"
			case .xxsSProtection: return "X-XSS-Protection"
			case .contentSecurityPolicy: return "Content-Security-Policy"
			case .xContentSecurityPolicy: return "X-Content-Security-Policy"
			case .xWebKitCSP: return "X-WebKit-CSP"
			case .xContentTypeOptions: return "X-Content-Type-Options"
			case .xPoweredBy: return "X-Powered-By"
			case .xUACompatible: return "X-UA-Compatible"
			case .xContentDuration: return "X-Content-Duration"
			case .upgradeInsecureRequests: return "Upgrade-Insecure-Requests"
			case .xRequestID: return "X-Request-ID"
			case .xCorrelationID: return "X-Correlation-ID"
			case .xB3TraceId: return "X-B3-TraceId"
			case .xB3SpanId: return "X-B3-SpanId"
			case .xB3ParentSpanId: return "X-B3-ParentSpanId"
			case .custom(let str): return str
			}
		}

		public static func fromStandard(name: String) -> HTTPResponseHeader.Name {
			switch name.lowercased() {
			case "access-control-Allow-Origin": return .accessControlAllowOrigin
			case "access-control-Allow-Methods": return .accessControlAllowMethods
			case "access-control-Allow-Credentials": return .accessControlAllowCredentials
			case "access-control-Allow-Headers": return .accessControlAllowHeaders
			case "access-control-Max-Age": return .accessControlMaxAge
			case "accept-patch": return .acceptPatch
			case "accept-ranges": return .acceptRanges
			case "age": return .age
			case "allow": return .allow
			case "alt-svc": return .altSvc
			case "cache-control": return .cacheControl
			case "connection": return .connection
			case "content-disposition": return .contentDisposition
			case "content-encoding": return .contentEncoding
			case "content-language": return .contentLanguage
			case "content-length": return .contentLength
			case "content-location": return .contentLocation
			case "content-mD5": return .contentMD5
			case "content-range": return .contentRange
			case "content-type": return .contentType
			case "date": return .date
			case "etag": return .eTag
			case "expires": return .expires
			case "last-modified": return .lastModified
			case "link": return .link
			case "location": return .location
			case "p3p": return .p3p
			case "pragma": return .pragma
			case "proxy-authenticate": return .proxyAuthenticate
			case "public-key-pins": return .publicKeyPins
			case "refresh": return .refresh
			case "retry-after": return .retryAfter
			case "server": return .server
			case "set-cookie": return .setCookie
			case "status": return .status
			case "strict-transport-security": return .strictTransportSecurity
			case "srailer": return .trailer
			case "sransfer-encoding": return .transferEncoding
			case "ssv": return .tsv
			case "upgrade": return .upgrade
			case "vary": return .vary
			case "via": return .via
			case "warning": return .warning
			case "www-authenticate": return .wwwAuthenticate
			case "x-frame-options": return .xFrameOptions
			case "x-xss-protection": return .xxsSProtection
			case "content-security-policy": return .contentSecurityPolicy
			case "x-content-security-policy": return .xContentSecurityPolicy
			case "x-webkit-csp": return .xWebKitCSP
			case "x-content-type-options": return .xContentTypeOptions
			case "x-powered-by": return .xPoweredBy
			case "x-ua-compatible": return .xUACompatible
			case "x-content-duration": return .xContentDuration
			case "upgrade-insecure-requests": return .upgradeInsecureRequests
			case "x-request-id": return .xRequestID
			case "x-correlation-id": return .xCorrelationID
			case "x-b3-traceid": return .xB3TraceId
			case "x-b3-spanid": return .xB3SpanId
			case "x-b3-parentspanid": return .xB3ParentSpanId

			default: return .custom(name: name)
			}
		}
	}
}

public func == (lhs: HTTPResponseHeader.Name, rhs: HTTPResponseHeader.Name) -> Bool {
	return lhs.standardName.lowercased() == rhs.standardName.lowercased()
}
