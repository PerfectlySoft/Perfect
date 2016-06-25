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

public protocol HTTPRequest: class {
    var method: HTTPMethod { get }
    var path: String { get }
    var queryParams: [(String, String)] { get }
    var protocolVersion: (Int, Int) { get }
    var remoteAddress: (host: String, port: UInt16) { get }
    var serverAddress: (host: String, port: UInt16) { get }
    var serverName: String { get }
    var documentRoot: String { get }
    var connection: NetTCP { get }
    var urlVariables: [String:String] { get set }
    
    func header(_ named: HTTPRequestHeader.Name) -> String?
    func addHeader(_ named: HTTPRequestHeader.Name, value: String)
    func setHeader(_ named: HTTPRequestHeader.Name, value: String)
    
    var headers: AnyIterator<(HTTPRequestHeader.Name, String)> { get }
    
    // impl note: these xParams vars could be implimented as a protocol extension parsing the raw
    // query/post string
    // but they are likely to be called several times and the required parsing would 
    // incur unwanted overhead
    
    var postParams: [(String, String)] { get }
    var postBodyBytes: [UInt8]? { get }
    var postBodyString: String? { get }
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
    
    public var uri: String {
        if self.queryParams.count == 0 {
            return self.path
        }
        return "\(self.path)?\(self.queryParams.map { return "\($0.0.stringByEncodingURL)=\($0.1.stringByEncodingURL)" }.joined(separator: "&")))"
    }
    
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
