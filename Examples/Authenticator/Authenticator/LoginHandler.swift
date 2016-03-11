//
//  LoginHandler.swift
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

