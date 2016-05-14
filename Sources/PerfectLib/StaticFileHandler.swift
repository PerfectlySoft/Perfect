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
	
	public init() {}
	
	public func handleRequest(request: WebRequest, response: WebResponse) {
		
		var requestUri = request.requestURI ?? ""
		if requestUri.hasSuffix("/") {
			requestUri.append("index.html") // !FIX! needs to be configurable
		}
		let documentRoot = request.documentRoot
		let file = File(documentRoot + "/" + requestUri)
		
		guard file.exists() else {
			response.setStatus(code: 404, message: "Not Found")
			response.appendBody(string: "The file \(requestUri) was not found.")
			// !FIX! need 404.html or some such thing
			response.requestCompleted()
			return
		}
		
		self.sendFile(response: response, file: file)
		response.requestCompleted()
	}
	
	func sendFile(response response: WebResponse, file: File) {
		
		defer {
			file.close()
		}
		
		let size = file.size()
		response.setStatus(code: 200, message: "OK")
		
		do {
			let bytes = try file.readSomeBytes(count: size)
			response.addHeader(name: "Content-type", value: MimeType.forExtension(file.path().pathExtension))
			response.appendBody(bytes: bytes)
		} catch {
			response.setStatus(code: 500, message: "Internal server error")
		}
	}
}
