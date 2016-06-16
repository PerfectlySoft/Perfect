//
//  StaticFileHandler.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2016-01-06.
//  Copyright © 2016 PerfectlySoft. All rights reserved.
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

/// A web request handler which can be used to return static disk-based files to the client.
/// Supports byte ranges, ETags and streaming very large files.
public struct StaticFileHandler {
	
	let chunkedBufferSize = 1024*200
	
    /// Public initializer
	public init() {}
	
    /// Main entry point. A registered URL handler should call this and pass the request and response objects.
    /// After calling this, the StaticFileHandler owns the request and will handle it until completion.
	public func handleRequest(request req: WebRequest, response: WebResponse) {
		
		var requestUri = req.requestURI ?? "/"
        if requestUri.isEmpty {
            requestUri = "/"
        }
		if requestUri[requestUri.index(before: requestUri.endIndex)] == "/" {
			requestUri.append("index.html") // !FIX! needs to be configurable
		}
		let documentRoot = req.documentRoot
		let file = File(documentRoot + "/" + requestUri)
		
		guard file.exists else {
			response.setStatus(code: 404, message: "Not Found")
			response.appendBody(string: "The file \(requestUri) was not found.")
			// !FIX! need 404.html or some such thing
			response.requestCompleted()
			return
		}
		
		self.sendFile(request: req, response: response, file: file)
	}
	
	func sendFile(request req: WebRequest, response resp: WebResponse, file: File) {
		
		resp.addHeader(name: "Accept-Ranges", value: "bytes")
        
		if let rangeRequest = req.header(named: "Range") {
			
			return self.performRangeRequest(rangeRequest: rangeRequest, request: req, response: resp, file: file)
            
        } else if let ifNoneMatch = req.header(named: "If-None-Match") {
            let eTag = self.getETag(file: file)
            if ifNoneMatch == eTag {
                resp.setStatus(code: 304, message: "NOT MODIFIED")
                return resp.requestCompleted()
            }
        }
        
        let size = file.size
        let contentType = MimeType.forExtension(file.path.pathExtension)
        
		resp.setStatus(code: 200, message: "OK")
		resp.addHeader(name: "Content-Type", value: contentType)
		resp.addHeader(name: "Content-Length", value: "\(size)")
        
        self.addETag(response: resp, file: file)
        
		if case .head = req.requestMethod {
			return resp.requestCompleted()
		}
		
		self.sendFile(remainingBytes: size, response: resp, file: file) {
			ok in
			file.close()
			resp.requestCompleted()
		}
	}
	
    func performRangeRequest(rangeRequest: String, request: WebRequest, response: WebResponse, file: File) {
        let size = file.size
        let ranges = self.parseRangeHeader(fromHeader: rangeRequest, max: size)
        if ranges.count == 1 {
            let range = ranges[0]
            let rangeCount = range.count
            let contentType = MimeType.forExtension(file.path.pathExtension)
            
            response.setStatus(code: 206, message: "Partial Content")
            response.addHeader(name: "Content-Length", value: "\(rangeCount)")
            response.addHeader(name: "Content-Type", value: contentType)
            response.addHeader(name: "Content-Range", value: "bytes \(range.lowerBound)-\(range.upperBound-1)/\(size)")
            
            if case .head = request.requestMethod {
                return response.requestCompleted()
            }
            
            let _ = file.marker = range.lowerBound
            
            return self.sendFile(remainingBytes: rangeCount, response: response, file: file) {
                ok in
                
                file.close()
                response.requestCompleted()
            }
        } else if ranges.count > 0 {
            // !FIX! support multiple ranges
            response.setStatus(code: 500, message: "INTERNAL SERVER ERROR")
            return response.requestCompleted()
        }
    }
    
    func getETag(file f: File) -> String {
        let eTagStr = f.internalPath + "\(f.modificationTime)"
        let eTag = eTagStr.utf8.sha1
        let eTagReStr = eTag.map { $0.hexString }.joined(separator: "")
        
        return eTagReStr
    }
    
    func addETag(response resp: WebResponse, file: File) {
        let eTag = self.getETag(file: file)
        
        resp.addHeader(name: "ETag", value: eTag)
    }
    
	func sendFile(remainingBytes remaining: Int, response: WebResponse, file: File, completion: (Bool) -> ()) {
		
		let thisRead = min(chunkedBufferSize, remaining)
		do {
			let bytes = try file.readSomeBytes(count: thisRead)
			response.appendBody(bytes: bytes)
			response.pushBody {
				ok in
				
				if !ok || thisRead == remaining {
					// done
					completion(ok)
				} else {
					self.sendFile(remainingBytes: remaining - bytes.count, response: response, file: file, completion: completion)
				}
			}
		} catch {
			completion(false)
		}
	}
	
	// bytes=0-3/7-9/10-15
	func parseRangeHeader(fromHeader header: String, max: Int) -> [Range<Int>] {
		let initialSplit = header.characters.split(separator: "=")
		guard initialSplit.count == 2 && String(initialSplit[0]) == "bytes" else {
			return [Range<Int>]()
		}
		
		let ranges = initialSplit[1]
		return ranges.split(separator: "/").flatMap { self.parseOneRange(fromString: String($0), max: max) }
	}
	
	// 0-3
	// 0-
	func parseOneRange(fromString string: String, max: Int) -> Range<Int>? {
		let split = string.characters.split(separator: "-")
		
		if split.count == 1 {
			guard let lower = Int(String(split[0])) else {
				return nil
			}
			return Range(uncheckedBounds: (lower, max))
		}
		
		guard let lower = Int(String(split[0])), upper = Int(String(split[1])) else {
			return nil
		}
		
		return Range(uncheckedBounds: (lower, upper+1))
	}
}



