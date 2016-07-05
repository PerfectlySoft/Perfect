//
//  HTTPRequest.swift
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
//

import PerfectNet

/// An HTTP based request object.
/// Contains all HTTP header and content data submitted by gthe client.
public protocol HTTPRequest: class {
	/// The HTTP request method.
    var method: HTTPMethod { get set }
	/// The request path.
    var path: String { get set }
	/// The partsed and decoded query/search arguments.
    var queryParams: [(String, String)] { get }
	/// The HTTP protocol version.
    var protocolVersion: (Int, Int) { get }
	/// The IP address and connecting port of the client.
    var remoteAddress: (host: String, port: UInt16) { get }
	/// The IP address and listening port for the server.
    var serverAddress: (host: String, port: UInt16) { get }
	/// The canonical name for the server.
    var serverName: String { get }
	/// The server's document root from which static file content will generally be served.
    var documentRoot: String { get }
	/// The TCP connection for this request.
    var connection: NetTCP { get }
	/// Any URL variables acquired during routing the path to the request handler.
    var urlVariables: [String:String] { get set }
    /// Returns the requested incoming header value.
	func header(_ named: HTTPRequestHeader.Name) -> String?
	/// Add a header to the response.
	/// No check for duplicate or repeated headers will be made.
	func addHeader(_ named: HTTPRequestHeader.Name, value: String)
	/// Set the indicated header value.
	/// If the header already exists then the existing value will be replaced.
    func setHeader(_ named: HTTPRequestHeader.Name, value: String)
    /// Provide access to all current header values.
    var headers: AnyIterator<(HTTPRequestHeader.Name, String)> { get }
    
    // impl note: these xParams vars could be implimented as a protocol extension parsing the raw
    // query/post string
    // but they are likely to be called several times and the required parsing would 
    // incur unwanted overhead
	
	/// Any parsed and decoded POST body parameters.
	/// If the POST content type is multipart/form-data then these will contain only the 
	/// non-file upload parameters.
    var postParams: [(String, String)] { get }
	/// POST body data as raw bytes.
	/// If the POST content type is multipart/form-data then this will be nil.
    var postBodyBytes: [UInt8]? { get set }
	/// POST body data treated as UTF-8 bytes and decoded into a String, if possible.
	/// If the POST content type is multipart/form-data then this will be nil.
    var postBodyString: String? { get }
	/// If the POST content type is multipart/form-data then this will contain the decoded form 
	/// parameters and file upload data. 
	/// This value will be nil if the request is not POST or did not have a multipart/form-data 
	/// content type.
    var postFileUploads: [MimeReader.BodySpec]? { get }
}

public extension HTTPRequest {
    
    /// Returns the first GET or POST parameter with the given name
    /// Returns the supplied default value if the parameter was not found
    public func param(name: String, defaultValue: String? = nil) -> String? {
        for p in self.queryParams
            where p.0 == name {
                return p.1
        }
        for p in self.postParams
            where p.0 == name {
                return p.1
        }
        return defaultValue
    }
    
    /// Returns all GET or POST parameters with the given name
    public func params(named: String) -> [String] {
        let a = self.params().filter { $0.0 == named }.map { $0.1 }
        return a
    }
    
    /// Returns all GET or POST parameters
    public func params() -> [(String, String)] {
        let a = self.queryParams + self.postParams
        return a
    }
}

public extension HTTPRequest {
    /// Returns the full request URI
    public var uri: String {
        if self.queryParams.count == 0 {
            return self.path
        }
        return "\(self.path)?\(self.queryParams.map { return "\($0.0.stringByEncodingURL)=\($0.1.stringByEncodingURL)" }.joined(separator: "&")))"
    }
    /// Returns all the cookie name/value pairs parsed from the request.
    public var cookies: [(String, String)] {
        guard let cookie = self.header(.cookie) else {
            return [(String, String)]()
        }
        return cookie.characters.split(separator: ";").flatMap {
            let d = $0.split(separator: "=").flatMap { String($0).stringByDecodingURL }
            guard d.count == 2 else { return nil }
            return (d[0], d[1])
        }
    }
}
