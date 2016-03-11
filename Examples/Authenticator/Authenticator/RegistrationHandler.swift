//
//  RegistrationHandler.swift
//  Authenticator
//
//  Created by Kyle Jessup on 2015-11-10.
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
		return MustacheEvaluationContext.MapType() // unreachable
	}
}
