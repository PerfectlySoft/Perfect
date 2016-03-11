//
//  AuthenticatingHandler.swift
//  Authenticator
//
//  Created by Kyle Jessup on 2015-11-09.
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

// Handler class
// When referenced in a mustache template, this class will be instantiated to handle the request
// and provide a set of values which will be used to complete the template.
class AuthenticatingHandler: PageHandler {
	
	// We set this property if the user is successfully validated.
	var authenticatedUser: User?
	
	// This is the function which all handlers must impliment.
	// It is called by the system to allow the handler to return the set of values which will be used when populating the template.
	// - parameter context: The MustacheEvaluationContext which provides access to the WebRequest containing all the information pertaining to the request
	// - parameter collector: The MustacheEvaluationOutputCollector which can be used to adjust the template output. For example a `defaultEncodingFunc` could be installed to change how outgoing values are encoded.
	func valuesForResponse(context: MustacheEvaluationContext, collector: MustacheEvaluationOutputCollector) throws -> MustacheEvaluationContext.MapType {
		
		// The dictionary which we will return
		let values = MustacheEvaluationContext.MapType()
		
		if let response = context.webResponse, let request = context.webRequest {
		
			let auth = request.httpAuthorization()
			if let digest = auth["type"] where digest == "Digest" {
				
				let username = auth["username"] ?? ""
				let nonce = auth["nonce"]
				let nc = auth["nc"]
				let uri = auth["uri"] ?? request.requestURI()
				let cnonce = auth["cnonce"]
				let qop = "auth"
				let method = auth["method"] ?? request.requestMethod()
				let authResponse = auth["response"]
				
				if authResponse != nil && nonce != nil && nc != nil && cnonce != nil {
					if let userTest = User(email: username) {
						let ha1 = userTest.authKey
						let ha2 = toHex((method+":"+uri).md5)
						let compareResponse = toHex((ha1+":"+nonce!+":"+nc!+":"+cnonce!+":"+qop+":"+ha2).md5)
						if authResponse! == compareResponse {
							response.setStatus(200, message: "OK")
							self.authenticatedUser = userTest
						}
					}
				}
			}
			
			if self.authenticatedUser == nil {
				
				let nonce = SessionManager.generateSessionKey()
				let headerValue = "Digest realm=\"\(AUTH_REALM)\", qop=\"auth\", nonce=\"\(nonce)\", uri=\"\(request.requestURI())\", algorithm=\"md5\""
								
				response.setStatus(401, message: "Unauthorized")
				response.replaceHeader("WWW-Authenticate", value: headerValue)
			}
		} else {
			fatalError("This is not a web request")
		}
		return values
	}
}

