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
    var headerStore = Array<(HTTPResponseHeader.Name, String)>()
    var bodyBytes = [UInt8]()
    
    var headers: AnyIterator<(HTTPResponseHeader.Name, String)> {
        var g = self.headerStore.makeIterator()
        return AnyIterator<(HTTPResponseHeader.Name, String)> {
            g.next()
        }
    }
    
    var connection: NetTCP {
        return request.connection
    }
    
    var isStreaming = false
    var wroteHeaders = false
    var completedCallback: (() -> ())?
    let request: HTTPRequest
    var cookies = [HTTPCookie]()
    
    lazy var isKeepAlive: Bool = {
        // http 1.1 is keep-alive unless otherwise noted
        // http 1.0 is keep-alive if specifically noted
        // check header first
        if let connection = self.request.header(.connection) {
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
    
    init(request: HTTPRequest) {
        self.request = request
        let net = request.connection
        self.completedCallback = {
            net.close()
        }
    }
    
    func completed() {
        if let cb = self.completedCallback {
            cb()
        }
    }
    
    func addCookie(_ cookie: HTTPCookie) {
        cookies.append(cookie)
    }
    
    func header(_ named: HTTPResponseHeader.Name) -> String? {
        for (n, v) in headerStore where n == named {
            return v
        }
        return nil
    }
    
    func addHeader(_ name: HTTPResponseHeader.Name, value: String) {
        headerStore.append((name, value))
    }
    
    func setHeader(_ name: HTTPResponseHeader.Name, value: String) {
        var fi = [Int]()
        for i in 0..<headerStore.count {
            let (n, _) = headerStore[i]
            if n == name {
                fi.append(i)
            }
        }
        fi = fi.reversed()
        for i in fi {
            headerStore.remove(at: i)
        }
        addHeader(name, value: value)
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
            addHeader(.connection, value: "keep-alive")
        }
        if isStreaming {
            addHeader(.transferEncoding, value: "chunked")
        }
        addCookies()
        var responseString = "HTTP/\(request.protocolVersion.0).\(request.protocolVersion.1) \(status)\r\n"
        for (n, v) in headers {
            responseString.append("\(n.standardName): \(v)\r\n")
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
    
    func addCookies() {
        for cookie in self.cookies {
            var cookieLine = ""
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
                    let formattedDate = try! formatDate(getNow() + secondsToICUDate(seconds*60),
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
            addHeader(.setCookie, value: cookieLine)
        }
        self.cookies.removeAll()
    }
}
















