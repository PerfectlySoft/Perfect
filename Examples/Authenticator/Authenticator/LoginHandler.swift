//
//  LoginHandler.swift
//  Authenticator
//
//  Created by Kyle Jessup on 2015-11-10.
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
import Foundation

// Handler class
// When referenced in a mustache template, this class will be instantiated to handle the request
// and provide a set of values which will be used to complete the template.
class LoginHandler: AuthenticatingHandler { // all template handlers must inherit from PageHandler
	
	// This is the function which all handlers must impliment.
	// It is called by the system to allow the handler to return the set of values which will be used when populating the template.
	// - parameter context: The MustacheEvaluationContext which provides access to the WebRequest containing all the information pertaining to the request
	// - parameter collector: The MustacheEvaluationOutputCollector which can be used to adjust the template output. For example a `defaultEncodingFunc` could be installed to change how outgoing values are encoded.
	override func valuesForResponse(context: MustacheEvaluationContext, collector: MustacheEvaluationOutputCollector) throws -> MustacheEvaluationContext.MapType {
		
		var values = try super.valuesForResponse(context, collector: collector)
		
		if let acceptStr = context.webRequest?.httpAccept() {
			if acceptStr.contains("json") {
				values["json"] = true
			}
		}
		
		guard let user = self.authenticatedUser else {
			// Our parent class will have set the web response code to trigger authentication.
			values["message"] = "Not authenticated"
			values["resultCode"] = 401
			return values
		}
		
		// This handler is responsible for taking a user supplied username and the associated
		// digest authentication information and validating it against the information in the database.
		values["resultCode"] = 0
		values["first"] = user.firstName
		values["last"] = user.lastName
		values["email"] = user.email
		values["title"] = "Perfect Project Template"
		values["message"] = "Logged in successfully!"
		
		// Return the values
		// These will be used to populate the template
		return values
	}
	
}

