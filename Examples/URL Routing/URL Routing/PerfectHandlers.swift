//
//  PerfectHandlers.swift
//  URL Routing
//
//  Created by Kyle Jessup on 2015-12-15.
//	Copyright (C) 2015 PerfectlySoft, Inc.
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

import PerfectLib

// This is the function which all Perfect Server modules must expose.
// The system will load the module and call this function.
// In here, register any handlers or perform any one-time tasks.
public func PerfectServerModuleInit() {
	
	// Install the built-in routing handler.
	// Using this system is optional and you could install your own system if desired.
	Routing.Handler.registerGlobally()
	
	Routing.Routes["GET", ["/", "index.html"] ] = { (_:WebResponse) in return IndexHandler() }
	Routing.Routes["/foo/*/baz"] = { _ in return EchoHandler() }
	Routing.Routes["/foo/bar/baz"] = { _ in return EchoHandler() }
	Routing.Routes["GET", "/user/{id}/baz"] = { _ in return Echo2Handler() }
	Routing.Routes["POST", "/user/{id}/baz"] = { _ in return Echo3Handler() }
	
	// Check the console to see the logical structure of what was installed.
	print("\(Routing.Routes)")
}

class IndexHandler: RequestHandler {
	
	func handleRequest(request: WebRequest, response: WebResponse) {
		response.appendBodyString("Index handler: You accessed path \(request.pathInfo())")
		response.requestCompletedCallback()
	}
}

class EchoHandler: RequestHandler {
	
	func handleRequest(request: WebRequest, response: WebResponse) {
		response.appendBodyString("Echo handler: You accessed path \(request.pathInfo()) with variables \(request.urlVariables)")
		response.requestCompletedCallback()
	}
}

class Echo2Handler: RequestHandler {
	
	func handleRequest(request: WebRequest, response: WebResponse) {
		response.appendBodyString("<html><body>Echo 2 handler: You GET accessed path \(request.pathInfo()) with variables \(request.urlVariables)<br>")
		response.appendBodyString("<form method=\"POST\" action=\"/user/\(request.urlVariables["id"] ?? "error")/baz\"><button type=\"submit\">POST</button></form></body></html>")
		response.requestCompletedCallback()
	}
}

class Echo3Handler: RequestHandler {
	
	func handleRequest(request: WebRequest, response: WebResponse) {
		response.appendBodyString("<html><body>Echo 3 handler: You POSTED to path \(request.pathInfo()) with variables \(request.urlVariables)</body></html>")
		response.requestCompletedCallback()
	}
}

