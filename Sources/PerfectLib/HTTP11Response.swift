//
//  HTTP11Response.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2016-06-21.
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

import PerfectNet
import PerfectThread

class HTTP11Response: HTTPResponse {
    var status = HTTPResponseStatus.ok
    var headers = [(String, String)]()
    var bodyBytes = [UInt8]()
    
    var connection: NetTCP {
        return request.connection
    }
    
    var isStreaming = false
    var wroteHeaders = false
    var completed: () -> ()
    
    lazy var isKeepAlive: Bool = {
        // http 1.1 is keep-alive unless otherwise noted
        // http 1.0 is keep-alive if specifically noted
        // check header first
        if let connection = self.request.headers["connection"] {
            if connection.lowercased() == "keep-alive" {
                return true
            }
            return false
        }
        return self.isHTTP11
    }()
    
    var isHTTP11: Bool {
        let version = self.request.protocolVersion
        return version.0 == 1 && version.1 == 1
    }
    
    let request: HTTPRequest
    
    init(request: HTTPRequest) {
        self.request = request
        self.completed = { request.connection.close() }
    }
    
    func addHeader(name: String, value: String) {
        headers.append((name, value))
    }
    
    func replaceHeader(name: String, value: String) {
        var fi = [Int]()
        for i in 0..<headers.count {
            let (n, _) = headers[i]
            if n == name {
                fi.append(i)
            }
        }
        fi.reverse()
        for i in fi {
            headers.remove(at: i)
        }
        addHeader(name: name, value: value)
    }
    
    func appendBody(bytes: [UInt8]) {
        bodyBytes.append(contentsOf: bytes)
    }
    
    func appendBody(string: String) {
        bodyBytes.append(contentsOf: [UInt8](string.utf8))
    }
    
    func setBody(json: [String:Any]) throws {
        let string = try json.jsonEncodedString()
        bodyBytes = [UInt8](string.utf8)
    }
    
    func flush(callback: (Bool) -> ()) {
        self.push {
            ok in
            guard ok else {
                return callback(false)
            }
            if self.isStreaming {
                self.appendBody(string: "0\r\n\r\n")
                self.pushNonStreamed(callback: callback)
            } else {
                callback(true)
            }
        }
    }
    
    func pushHeaders(callback: (Bool) -> ()) {
        wroteHeaders = true
        if isKeepAlive {
            addHeader(name: "connection", value: "keep-alive")
        }
        if isStreaming {
            addHeader(name: "transfer-encoding", value: "chunked")
        }
        var responseString = "HTTP/\(request.protocolVersion.0).\(request.protocolVersion.1) \(status)\r\n"
        for (n, v) in headers {
            responseString.append("\(n): \(v)\r\n")
        }
        responseString.append("\r\n")
        connection.write(string: responseString) {
            _ in
            self.push(callback: callback)
        }
    }
    
    func push(callback: (Bool) -> ()) {
        if !wroteHeaders {
            pushHeaders(callback: callback)
        } else if isStreaming {
            pushStreamed(callback: callback)
        } else {
            pushNonStreamed(callback: callback)
        }
    }
    
    func pushStreamed(callback: (Bool) -> ()) {
        let bodyCount = bodyBytes.count
        guard bodyCount > 0 else {
            return callback(true)
        }
        let hexString = "\(String(bodyCount, radix: 16, uppercase: true))\r\n"
        let sendA = Array(hexString.utf8)
        connection.write(bytes: sendA) {
            sent in
            guard sent == sendA.count else {
                return callback(false)
            }
            self.bodyBytes.append(httpCR)
            self.bodyBytes.append(httpLF)
            self.pushNonStreamed(callback: callback)
        }
    }
    
    func pushNonStreamed(callback: (Bool) -> ()) {
        let bodyCount = bodyBytes.count
        guard bodyCount > 0 else {
            return callback(true)
        }
        connection.write(bytes: bodyBytes) {
            sent in
            self.bodyBytes.removeAll()
            guard bodyCount == sent else {
                return callback(false)
            }
            Threading.dispatch {
                callback(true)
            }
        }
    }
}
















