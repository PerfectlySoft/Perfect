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

public class StaticFileHandler: RequestHandler {
	
	public init() {}
	
	public func handleRequest(request: WebRequest, response: WebResponse) {
		
		var requestUri = request.requestURI()
		if requestUri.hasSuffix("/") {
			requestUri.appendContentsOf("index.html") // !FIX! needs to be configurable
		}
		let documentRoot = request.documentRoot
		let file = File(documentRoot + "/" + requestUri)
		
		guard file.exists() else {
			response.setStatus(404, message: "Not Found")
			response.appendBodyString("The file \(requestUri) was not found.")
			// !FIX! need 404.html or some such thing
			response.requestCompletedCallback()
			return
		}
		
		self.sendFile(response, file: file)
		response.requestCompletedCallback()
	}
	
	func sendFile(response: WebResponse, file: File) {
		
		defer {
			file.close()
		}
		
		let size = file.size()
		response.setStatus(200, message: "OK")
		
		do {
			let bytes = try file.readSomeBytes(size)
			response.addHeader("Content-type", value: MimeType.forExtension(file.path().pathExtension))
			response.appendBodyBytes(bytes)
		} catch {
			response.setStatus(500, message: "Internal server error")
		}
	}
}
