//
//  HTTP11Request.swift
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

private let httpMaxHeadersSize = 1024 * 8

private let characterCR: Character = "\r"
private let characterLF: Character = "\n"
private let characterCRLF: Character = "\r\n"
private let characterSP: Character = " "
private let characterHT: Character = "\t"
private let characterColon: Character = ":"

private let httpReadSize = 1024 * 4
private let httpReadTimeout = 5.0

let httpLF: UInt8 = 10
let httpCR: UInt8 = 13

private let httpSpace = UnicodeScalar(32)
private let httpQuestion = UnicodeScalar(63)


class HTTP11Request: HTTPRequest {
    var method: HTTPMethod  = .get
    var path = ""
    var queryString = ""
    
    lazy var queryParams: [(String, String)] = {
        return self.deFormURLEncoded(string: self.queryString)
    }()
    
    var protocolVersion = (1, 0)
    var remoteAddress = (host: "", port: 0 as UInt16)
    var serverAddress = (host: "", port: 0 as UInt16)
    var serverName = ""
    var documentRoot = "./webroot"
    var urlVariables = [String:String]()
    
    private var headerStore = Dictionary<HTTPRequestHeader.Name, String>()
    
    var headers: AnyIterator<(HTTPRequestHeader.Name, String)> {
        var g = self.headerStore.makeIterator()
        return AnyIterator<(HTTPRequestHeader.Name, String)> {
            guard let n = g.next() else {
                return nil
            }
            return (n.key, n.value)
        }
    }
    
    lazy var postParams: [(String, String)] = {
        
        if let mime = self.mimes {
            return mime.bodySpecs.filter { $0.file == nil }.map { ($0.fieldName, $0.fieldValue) }
        } else if let bodyString = self.postBodyString {
            return self.deFormURLEncoded(string: bodyString)
        }
        return [(String, String)]()
    }()
    
    var postBodyBytes: [UInt8]? {
        get {
            if let _ = mimes {
                return nil
            }
            return workingBuffer
        }
        set {
            if let nv = newValue {
                workingBuffer = nv
            } else {
                workingBuffer.removeAll()
            }
        }
    }
    var postBodyString: String? {
        guard let bytes = postBodyBytes else {
            return nil
        }
        if bytes.isEmpty {
            return ""
        }
        return UTF8Encoding.encode(bytes: bytes)
    }
    var postFileUploads: [MimeReader.BodySpec]? {
        guard let mimes = self.mimes else {
            return nil
        }
        return mimes.bodySpecs
    }
    
    var connection: NetTCP
    var workingBuffer = [UInt8]()
    var workingBufferOffset = 0
    
    var mimes: MimeReader?
    
    var contentType: String? {
        return self.headerStore[.contentType]
    }
    
    lazy var contentLength: Int = {
        guard let cl = self.headerStore[.contentLength] else {
            return 0
        }
        return Int(cl) ?? 0
    }()
    
    typealias StatusCallback = (HTTPResponseStatus) -> ()
    
    init(connection: NetTCP) {
        self.connection = connection
    }
    
    func header(_ named: HTTPRequestHeader.Name) -> String? {
        return headerStore[named]
    }
    
    func addHeader(_ named: HTTPRequestHeader.Name, value: String) {
        if let existing = headerStore[named] {
            if existing == "cookie" {
                self.headerStore[named] = existing + "; " + value
            } else {
                self.headerStore[named] = existing + ", " + value
            }
        } else {
            self.headerStore[named] = value
        }
    }
    
    func setHeader(_ named: HTTPRequestHeader.Name, value: String) {
        headerStore[named] = value
    }
    
    func setHeader(named: String, value: String) {
        let lowered = named.lowercased()
        setHeader(HTTPRequestHeader.Name.fromStandard(name: lowered), value: value)
    }
    
    func readRequest(callback: StatusCallback) {
        self.readHeaders { status in
            if case .ok = status {
                self.readBody(callback: callback)
            } else {
                callback(status)
            }
        }
    }
    
    func readHeaders(_ callback: StatusCallback) {
        self.connection.readSomeBytes(count: httpReadSize) {
            b in
            self.didReadHeaderData(b, callback: callback)
        }
    }
    
    func readBody(callback: StatusCallback) {
        let cl = self.contentLength
        guard cl > 0 else {
            return callback(.ok)
        }
        let workingDiff = self.workingBuffer.count - self.workingBufferOffset
        if workingDiff > 0 {
            // data remaining in working buffer
            let sub = Array(self.workingBuffer.suffix(workingDiff))
            self.workingBuffer.removeAll()
            self.putPostData(sub)
        } else {
            self.workingBuffer.removeAll()
        }
        self.workingBufferOffset = 0
        self.readBody(count: cl - workingDiff, callback: callback)
    }
    
    func readBody(count size: Int, callback: StatusCallback) {
        guard size > 0 else {
            return callback(.ok)
        }
        self.connection.readSomeBytes(count: size) {
            [weak self] b in
            if let b = b where b.count > 0 {
                self?.putPostData(b)
                self?.readBody(count: size - b.count, callback: callback)
            } else {
                self?.connection.readBytesFully(count: 1, timeoutSeconds: httpReadTimeout) {
                    b in
                    guard let b = b else {
                        return callback(.requestTimeout)
                    }
                    self?.putPostData(b)
                    self?.readBody(count: size - 1, callback: callback)
                }
            }
        }
    }
    
    func processRequestLine(_ lineStr: String) {
        
        var method = "", pathInfo = "", queryString = "", hvers = ""
        var gen = lineStr.unicodeScalars.makeIterator()
        
        // METHOD PATH_INFO[?QUERY] HVERS
        while let c = gen.next() {
            if httpSpace == c {
                break
            }
            method.append(c)
        }
        var gotQuest = false
        while let c = gen.next() {
            if httpSpace == c {
                break
            }
            if gotQuest {
                queryString.append(c)
            } else if httpQuestion == c {
                gotQuest = true
            } else {
                pathInfo.append(c)
            }
        }
        while let c = gen.next() {
            hvers.append(c)
        }
        
        self.method = HTTPMethod.methodFrom(string: method)
        self.path = pathInfo
        self.queryString = queryString
        
        if hvers == "1.1" {
            self.protocolVersion = (1, 1)
        }
        
        let (remoteHost, remotePort) = self.connection.peerName()
        
        self.remoteAddress = (remoteHost, remotePort)
    }
    
    func processHeaderLine(_ h: String) -> Bool {
        var fieldName = ""
        var fieldValue = ""
        
        let characters = h.characters
        let endIndex = characters.endIndex
        var currIndex = characters.startIndex
        
        while currIndex < endIndex {
            
            let c = characters[currIndex]
            currIndex = characters.index(after: currIndex)
            
            if c == characterColon {
                break
            }
            fieldName.append(c)
        }
        
        guard !fieldName.isEmpty else {
            return false
        }
        
        // skip LWS
        while currIndex < endIndex {
            
            let c = characters[currIndex]
            if c == characterSP || c == characterHT {
                currIndex = characters.index(after: currIndex)
            } else {
                break
            }
        }
        
        while currIndex < endIndex {
            
            let c = characters[currIndex]
            currIndex = characters.index(after: currIndex)
            
            if c == characterCRLF || c == characterLF {
                break
            }
            fieldValue.append(c)
        }
        
        self.setHeader(named: fieldName, value: fieldValue)
        return true
    }
    
    func pullOneHeaderLine(_ characters: String.CharacterView, range: Range<String.CharacterView.Index>) -> (String, Range<String.CharacterView.Index>) {
        
        // skip CRLF or LF
        var initial = range.lowerBound
        while initial < range.upperBound {
            
            let c = characters[initial]
            if c == characterCRLF || c == characterLF {
                initial = characters.index(after: initial)
                continue
            }
            break
        }
        
        var retStr = ""
        
        while initial < range.upperBound {
            var c = characters[initial]
            initial = characters.index(after: initial)
            
            if c == characterCRLF || c == characterLF {
                // check for folded header
                if initial >= range.upperBound {
                    return (retStr, initial..<range.upperBound)
                }
                c = characters[initial]
                
                if c == characterSP || c == characterHT {
                    initial = characters.index(after: initial)
                    continue
                } else {
                    return (retStr, initial..<range.upperBound)
                }
                //                } else if c == characterCR {
                //                    // a single CR is invalid. either broken client or shenanigans
                //                    return ("", range)
            } else {
                retStr.append(c)
            }
        }
        return ("", range)
    }
    
    func headerToString() -> String? {
        return String(validatingUTF8: UnsafePointer<CChar>(self.workingBuffer))
    }
    
    // The headers have been read completely
    // self.workingBufferOffset indicates the end of the headers
    // including the final terminating CRLF(LF) pair which has been replaced with 0s
    // self.workingBuffer[self.workingBufferOffset] marks the start of body data, if any
    func processCompleteHeaders(_ callback: StatusCallback) {
        guard let decodedHeaders = self.headerToString() else {
            return callback(.badRequest)
        }
        let characters = decodedHeaders.characters
        let (line, initialRange) = self.pullOneHeaderLine(characters, range: characters.startIndex..<characters.endIndex)
        guard !line.isEmpty else {
            return callback(.badRequest)
        }
        self.processRequestLine(line)
        var currentRange = initialRange
        while true {
            let tup = self.pullOneHeaderLine(characters, range: currentRange)
            guard !tup.0.isEmpty else {
                break
            }
            guard self.processHeaderLine(tup.0) else {
                return callback(.badRequest)
            }
            currentRange = tup.1
        }
        callback(.ok)
    }
    
    // scan the working buffer for the end of the headers
    // pass true to callback to indicate that the headers have all been read
    // pass false to indicate that the request is malformed or dead
    // if full headers have not been read, read more data
    // self.workingBufferOffset indicates where we start scanning
    // if the buffer ends on a single CR or CRLF pair, back the self.workingBufferOffset up
    func scanWorkingBuffer(_ callback: StatusCallback) {
        guard self.workingBuffer.count < httpMaxHeadersSize else {
            return callback(.requestEntityTooLarge)
        }
        let startingOffset = self.workingBufferOffset
        var lastCRLFPair = -1
        var i = startingOffset
        while i < self.workingBuffer.count {
            let c = self.workingBuffer[i]
            if c == httpLF {
                // this is a valid header end
                if lastCRLFPair != -1 {
                    self.workingBuffer[i] = 0
                    self.workingBufferOffset = i + 1
                    return self.processCompleteHeaders(callback)
                }
                lastCRLFPair = i
            } else if c == httpCR {
                guard i + 1 < self.workingBuffer.count else {
                    if i - workingBufferOffset > 2 { // guard for break immediately before trailing LF
                        self.workingBufferOffset = i
                    }
                    break
                }
                guard self.workingBuffer[i+1] == httpLF else {
                    // malformed header
                    return callback(.badRequest)
                }
                if lastCRLFPair != -1 {
                    self.workingBuffer[i] = 0
                    self.workingBuffer[i+1] = 0
                    self.workingBufferOffset = i + 2
                    return self.processCompleteHeaders(callback)
                }
                lastCRLFPair = i
                i += 1
            } else {
                lastCRLFPair = -1
            }
            i += 1
        }
        // not done yet
        self.readHeaders(callback)
    }
    
    func didReadHeaderData(_ b:[UInt8]?, callback: StatusCallback) {
        guard let b = b else {
            return callback(.requestTimeout)
        }
        if b.count == 0 { // no data was available for immediate consumption. try reading with timeout
            self.connection.readBytesFully(count: 1, timeoutSeconds: httpReadTimeout) {
                b2 in
                self.didReadHeaderData(b2, callback: callback)
            }
        } else {
            self.workingBuffer.append(contentsOf: b)
            self.scanWorkingBuffer(callback)
        }
    }
    
    func putPostData(_ b: [UInt8]) {
        if self.workingBuffer.count == 0 && self.mimes == nil {
            if let contentType = self.contentType where contentType.begins(with: "multipart/form-data") {
                self.mimes = MimeReader(contentType)
            }
        }
        if let mimes = self.mimes {
            return mimes.addToBuffer(bytes: b)
        } else {
            self.workingBuffer.append(contentsOf: b)
        }
    }
    
    func deFormURLEncoded(string: String) -> [(String, String)] {
        return string.characters.split(separator: "&").map(String.init).flatMap {
            let d = $0.characters.split(separator: "=").flatMap { String($0).stringByDecodingURL }
            if d.count == 2 { return (d[0], d[1]) }
            if d.count == 1 { return (d[0], "") }
            return nil
        }
    }
}
