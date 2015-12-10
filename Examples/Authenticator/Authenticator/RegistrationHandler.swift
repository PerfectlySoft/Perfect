//
//  RegistrationHandler.swift
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

// Handler class
// When referenced in a mustache template, this class will be instantiated to handle the request
// and provide a set of values which will be used to complete the template.
class RegistrationHandler: PageHandler { // all template handlers must inherit from PageHandler
	
	// This is the function which all handlers must impliment.
	// It is called by the system to allow the handler to return the set of values which will be used when populating the template.
	// - parameter context: The MustacheEvaluationContext which provides access to the WebRequest containing all the information pertaining to the request
	// - parameter collector: The MustacheEvaluationOutputCollector which can be used to adjust the template output. For example a `defaultEncodingFunc` could be installed to change how outgoing values are encoded.
	func valuesForResponse(context: MustacheEvaluationContext, collector: MustacheEvaluationOutputCollector) throws -> MustacheEvaluationContext.MapType {
		
		var json = false
		if let acceptStr = context.webRequest?.httpAccept() {
			if acceptStr.contains("json") {
				json = true
			}
		}
		
		// This handler is responsible for taking the information a user supplies when registering for a new account and putting it into the database.
		if let request = context.webRequest {
			
			// User submits a first name, last name, email address (used as login key) and password.
			if let fname = request.param("fname"),
				lname = request.param("lname"),
				email = request.param("email"),
				pass = request.param("password"),
				pass2 = request.param("password2") {
					
					// Ensure that the passwords match, avoiding simple typos
					guard pass == pass2 else {
						return ["title":"Registration Error", "message":"The passwords did not match.", "json":json, "resultCode":500]
					}
					
					// Ensure that the email is not already taken
					guard nil == User(email: email) else {
						return ["title":"Registration Error", "message":"The email address was already taken.", "json":json, "resultCode":500]
					}
					
					guard let _ = User.create(fname, last: lname, email: email, password: pass) else {
						return ["title":"Registration Error", "message":"The user was not able to be created.", "json":json, "resultCode":500]
					}
					// All is well
					return ["title":"Registration Successful", "message":"Registration Successful", "json":json, "resultCode":0, "first":fname, "last":lname, "email":email]
			}
		}
		return [String:Any]() // unreachable
	}
}
