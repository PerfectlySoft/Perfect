//
//  PerfectHandlers.swift
//  URL Routing
//
//  Created by Kyle Jessup on 2015-12-15.
//	Copyright (C) 2015 PerfectlySoft, Inc.
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
	Routing.Routes["GET", "/user/{id}"] = { _ in return Echo2Handler() }
	Routing.Routes["POST", "/user/{id}/baz"] = { _ in return Echo3Handler() }
	
	// Test this one via command line with curl:
	// curl --data "{\"id\":123}" http://0.0.0.0:8181/raw --header "Content-Type:application/json"
	Routing.Routes["POST", "/raw"] = { _ in return RawPOSTHandler() }
	
	// Check the console to see the logical structure of what was installed.
	print("\(Routing.Routes.description)")
}

class IndexHandler: RequestHandler {
	
	func handleRequest(request: WebRequest, response: WebResponse) {
		response.appendBodyString("Index handler: You accessed path \(request.requestURI())")
		response.requestCompletedCallback()
	}
}

class EchoHandler: RequestHandler {
	
	func handleRequest(request: WebRequest, response: WebResponse) {
		response.appendBodyString("Echo handler: You accessed path \(request.requestURI()) with variables \(request.urlVariables)")
		response.requestCompletedCallback()
	}
}

class Echo2Handler: RequestHandler {
	
	func handleRequest(request: WebRequest, response: WebResponse) {
		response.appendBodyString("<html><body>Echo 2 handler: You GET accessed path \(request.requestURI()) with variables \(request.urlVariables)<br>")
		response.appendBodyString("<form method=\"POST\" action=\"/user/\(request.urlVariables["id"] ?? "error")/baz\"><button type=\"submit\">POST</button></form></body></html>")
		response.requestCompletedCallback()
	}
}

class Echo3Handler: RequestHandler {
	
	func handleRequest(request: WebRequest, response: WebResponse) {
		response.appendBodyString("<html><body>Echo 3 handler: You POSTED to path \(request.requestURI()) with variables \(request.urlVariables)</body></html>")
		response.requestCompletedCallback()
	}
}

class RawPOSTHandler: RequestHandler {
	
	func handleRequest(request: WebRequest, response: WebResponse) {
		response.appendBodyString("<html><body>Raw POST handler: You POSTED to path \(request.requestURI()) with content-type \(request.contentType()) and POST body \(request.postBodyString)</body></html>")
		response.requestCompletedCallback()
	}
}

