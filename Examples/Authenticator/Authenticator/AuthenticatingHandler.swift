//
//  AuthenticatingHandler.swift
//  Authenticator
//
//  Created by Kyle Jessup on 2015-11-09.
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

