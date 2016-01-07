//
//  StaticFileHandler.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2016-01-06.
//  Copyright © 2016 PerfectlySoft. All rights reserved.
//
//	This program is free software: you can redistribute it and/or modify
//	it under the terms of the GNU Affero General Public License as
//	published by the Free Software Foundation, either version 3 of the
//	License, or (at your option) any later version, as supplemented by the
//	Perfect Additional Terms.
//
//	This program is distributed in the hope that it will be useful,
//	but WITHOUT ANY WARRANTY; without even the implied warranty of
//	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//	GNU Affero General Public License, as supplemented by the
//	Perfect Additional Terms, for more details.
//
//	You should have received a copy of the GNU Affero General Public License
//	and the Perfect Additional Terms that immediately follow the terms and
//	conditions of the GNU Affero General Public License along with this
//	program. If not, see <http://www.perfect.org/AGPL_3_0_With_Perfect_Additional_Terms.txt>.
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
