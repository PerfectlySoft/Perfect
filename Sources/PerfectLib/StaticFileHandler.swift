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

public struct StaticFileHandler {
	
	let chunkedBufferSize = 1024*200
	
	public init() {}
	
	public func handleRequest(request req: WebRequest, response: WebResponse) {
		
		var requestUri = req.requestURI ?? ""
		if requestUri.ends(with: "/") {
			requestUri.append("index.html") // !FIX! needs to be configurable
		}
		let documentRoot = req.documentRoot
		let file = File(documentRoot + "/" + requestUri)
		
		guard file.exists() else {
			response.setStatus(code: 404, message: "Not Found")
			response.appendBody(string: "The file \(requestUri) was not found.")
			// !FIX! need 404.html or some such thing
			response.requestCompleted()
			return
		}
		
		self.sendFile(request: req, response: response, file: file)
	}
	
	func sendFile(request req: WebRequest, response resp: WebResponse, file: File) {
		
		let contentType = MimeType.forExtension(file.path().pathExtension)
		let size = file.size()
		
		resp.addHeader(name: "Accept-Ranges", value: "bytes")
		
		if let rangeRequest = resp.request.header(named: "Range") {
			
			let ranges = self.parseRangeHeader(fromHeader: rangeRequest, max: size)
			if ranges.count == 1 {
				let range = ranges[0]
				let rangeCount = range.count
				
				resp.setStatus(code: 206, message: "Partial Content")
				resp.addHeader(name: "Content-Length", value: "\(rangeCount)")
				resp.addHeader(name: "Content-Type", value: contentType)
				resp.addHeader(name: "Content-Range", value: "bytes \(range.lowerBound)-\(range.upperBound-1)/\(size)")
				
				if case .Head = req.requestMethod {
					return resp.requestCompleted()
				}
				
				file.setMarker(to: range.lowerBound)
				
				return self.sendFile(remainingBytes: rangeCount, response: resp, file: file) {
					ok in
					
					file.close()
					resp.requestCompleted()
				}
			} else if ranges.count > 0 {
				
			}
		}
		
		resp.setStatus(code: 200, message: "OK")
		resp.addHeader(name: "Content-Type", value: contentType)
		resp.addHeader(name: "Content-Length", value: "\(size)")
		
		if case .Head = req.requestMethod {
			return resp.requestCompleted()
		}
		
		self.sendFile(remainingBytes: size, response: resp, file: file) {
			ok in
			file.close()
			resp.requestCompleted()
		}
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



