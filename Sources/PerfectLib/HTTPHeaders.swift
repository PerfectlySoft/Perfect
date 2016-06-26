//
//  HTTPHeaders.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2016-06-17.
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

/// An HTTP request header.
public enum HTTPRequestHeader {
    /// A header name type. Each has a corresponding value type.
    public enum Name: Hashable {
        case accept, acceptCharset, acceptEncoding, acceptLanguage, acceptDatetime, authorization
        case cacheControl, connection, cookie, contentLength, contentMD5, contentType
        case date, expect, forwarded, from, host
        case ifMatch, ifModifiedSince, ifNoneMatch, ifRange, ifUnmodifiedSince
        case maxForwards, origin, pragma, proxyAuthorization, range, referer
        case te, userAgent, upgrade, via, warning, xRequestedWith, dnt
        case xForwardedFor, xForwardedHost, xForwardedProto
        case frontEndHttps, xHttpMethodOverride, xATTDeviceId, xWapProfile
        case proxyConnection, xUIDH, xCsrfToken
        case custom(name: String)
        
        public var hashValue: Int {
            return self.standardName.hashValue
        }
        
        public var standardName: String {
            switch self {
            case .accept: return "accept"
            case .acceptCharset: return "accept-charset"
            case .acceptEncoding: return "accept-encoding"
            case .acceptLanguage: return "accept-language"
            case .acceptDatetime: return "accept-datetime"
            case .authorization: return "authorization"
            case .cacheControl: return "cache-control"
            case .connection: return "connection"
            case .cookie: return "cookie"
            case .contentLength: return "content-length"
            case .contentMD5: return "content-md5"
            case .contentType: return "content-type"
            case .date: return "date"
            case .expect: return "expect"
            case .forwarded: return "forwarded"
            case .from: return "from"
            case .host: return "host"
            case .ifMatch: return "if-match"
            case .ifModifiedSince: return "if-modified-since"
            case .ifNoneMatch: return "if-none-match"
            case .ifRange: return "if-range"
            case .ifUnmodifiedSince: return "if-unmodified-since"
            case .maxForwards: return "max-forwards"
            case .origin: return "origin"
            case .pragma: return "pragma"
            case .proxyAuthorization: return "proxy-authorization"
            case .range: return "range"
            case .referer: return "referer"
            case .te: return "te"
            case .userAgent: return "user-agent"
            case .upgrade: return "upgrade"
            case .via: return "via"
            case .warning: return "warning"
            case .xRequestedWith: return "x-requested-with"
            case .dnt: return "dnt"
            case .xForwardedFor: return "x-forwarded-for"
            case .xForwardedHost: return "x-forwarded-host"
            case .xForwardedProto: return "x-forwarded-proto"
            case .frontEndHttps: return "front-end-https"
            case .xHttpMethodOverride: return "x-http-method-override"
            case .xATTDeviceId: return "x-att-deviceid"
            case .xWapProfile: return "x-wap-profile"
            case .proxyConnection: return "proxy-connection"
            case .xUIDH: return "x-uidh"
            case .xCsrfToken: return "x-csrf-token"
            case .custom(let str): return str.lowercased()
            }
        }
        
        public static let lookupTable: [String:HTTPRequestHeader.Name] = [
            "accept":.accept,
            "accept-charset":.acceptCharset,
            "accept-encoding":.acceptEncoding,
            "accept-language":.acceptLanguage,
            "accept-datetime":.acceptDatetime,
            "authorization":.authorization,
            "cache-control":.cacheControl,
            "connection":.connection,
            "cookie":.cookie,
            "content-length":.contentLength,
            "content-md5":.contentMD5,
            "content-type":.contentType,
            "date":.date,
            "expect":.expect,
            "forwarded":.forwarded,
            "from":.from,
            "host":.host,
            "if-match":.ifMatch,
            "if-modified-since":.ifModifiedSince,
            "if-none-match":.ifNoneMatch,
            "if-range":.ifRange,
            "if-unmodified-since":.ifUnmodifiedSince,
            "max-forwards":.maxForwards,
            "origin":.origin,
            "pragma":.pragma,
            "proxy-authorization":.proxyAuthorization,
            "range":.range,
            "referer":.referer,
            "te":.te,
            "user-agent":.userAgent,
            "upgrade":.upgrade,
            "via":.via,
            "warning":.warning,
            "x-requested-with":.xRequestedWith,
            "dnt":.dnt,
            "x-forwarded-for":.xForwardedFor,
            "x-forwarded-host":.xForwardedHost,
            "x-forwarded-proto":.xForwardedProto,
            "front-end-https":.frontEndHttps,
            "x-http-method-override":.xHttpMethodOverride,
            "x-att-deviceid":.xATTDeviceId,
            "x-wap-profile":.xWapProfile,
            "proxy-connection":.proxyConnection,
            "x-uidh":.xUIDH,
            "x-csrf-token":.xCsrfToken
        ]
        
        public static func fromStandard(name: String) -> HTTPRequestHeader.Name {
            if let found = HTTPRequestHeader.Name.lookupTable[name] {
                return found
            }
            return .custom(name: name)
        }
    }
}

public func ==(lhs: HTTPRequestHeader.Name, rhs: HTTPRequestHeader.Name) -> Bool {
    return lhs.standardName == rhs.standardName
}

/// A HTTP response header.
public enum HTTPResponseHeader {
    
    public enum Name {
        case accessControlAllowOrigin
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
        case custom(name: String)
        
        public var hashValue: Int {
            return self.standardName.hashValue
        }
        
        public var standardName: String {
            switch self {
            case .accessControlAllowOrigin: return "Access-Control-Allow-Origin"
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
            case .custom(let str): return str
            }
        }
        
        public static func fromStandard(name: String) -> HTTPResponseHeader.Name {
            switch name {
            case "Access-Control-Allow-Origin": return .accessControlAllowOrigin
            case "Accept-Patch": return .acceptPatch
            case "Accept-Ranges": return .acceptRanges
            case "Age": return .age
            case "Allow": return .allow
            case "Alt-Svc": return .altSvc
            case "Cache-Control": return .cacheControl
            case "Connection": return .connection
            case "Content-Disposition": return .contentDisposition
            case "Content-Encoding": return .contentEncoding
            case "Content-Language": return .contentLanguage
            case "Content-Length": return .contentLength
            case "Content-Location": return .contentLocation
            case "Content-MD5": return .contentMD5
            case "Content-Range": return .contentRange
            case "Content-Type": return .contentType
            case "Date": return .date
            case "ETag": return .eTag
            case "Expires": return .expires
            case "Last-Modified": return .lastModified
            case "Link": return .link
            case "Location": return .location
            case "P3P": return .p3p
            case "Pragma": return .pragma
            case "Proxy-Authenticate": return .proxyAuthenticate
            case "Public-Key-Pins": return .publicKeyPins
            case "Refresh": return .refresh
            case "Retry-After": return .retryAfter
            case "Server": return .server
            case "Set-Cookie": return .setCookie
            case "Status": return .status
            case "Strict-Transport-Security": return .strictTransportSecurity
            case "Trailer": return .trailer
            case "Transfer-Encoding": return .transferEncoding
            case "TSV": return .tsv
            case "Upgrade": return .upgrade
            case "Vary": return .vary
            case "Via": return .via
            case "Warning": return .warning
            case "WWW-Authenticate": return .wwwAuthenticate
            case "X-Frame-Options": return .xFrameOptions
            case "X-XSS-Protection": return .xxsSProtection
            case "Content-Security-Policy": return .contentSecurityPolicy
            case "X-Content-Security-Policy": return .xContentSecurityPolicy
            case "X-WebKit-CSP": return .xWebKitCSP
            case "X-Content-Type-Options": return .xContentTypeOptions
            case "X-Powered-By": return .xPoweredBy
            case "X-UA-Compatible": return .xUACompatible
            case "X-Content-Duration": return .xContentDuration
            case "Upgrade-Insecure-Requests": return .upgradeInsecureRequests
            case "X-Request-ID": return .xRequestID
            case "X-Correlation-ID": return .xCorrelationID
            default: return .custom(name: name)
            }
        }
    }
}

public func ==(lhs: HTTPResponseHeader.Name, rhs: HTTPResponseHeader.Name) -> Bool {
    return lhs.standardName == rhs.standardName
}
