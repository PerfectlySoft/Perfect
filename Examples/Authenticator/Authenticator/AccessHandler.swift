//
//  AccessHandler.swift
//  Authenticator
//
//  Created by Kyle Jessup on 2015-11-10.
//	Copyright (C) 2015 PerfectlySoft, Inc.
//
//     This program is free software: you can redistribute it and/or modify
//     it under the terms of the GNU Affero General Public License as published by
//     the Free Software Foundation, either version 3 of the License, or
//     (at your option) any later version.
//
//     This program is distributed in the hope that it will be useful,
//     but WITHOUT ANY WARRANTY; without even the implied warranty of
//     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//     GNU Affero General Public License for more details.
//
//     You should have received a copy of the GNU Affero General Public License
//     along with this program.  If not, see <http://www.gnu.org/licenses/>.
//

import PerfectLib

// Handler class
// When referenced in a moustache template, this class will be instantiated to handle the request
// and provide a set of values which will be used to complete the template.
class AccessHandler: AuthenticatingHandler { // all template handlers must inherit from PageHandler
	
	// This is the function which all handlers must impliment.
	// It is called by the system to allow the handler to return the set of values which will be used when populating the template.
	// - parameter context: The MoustacheEvaluationContext which provides access to the WebRequest containing all the information pertaining to the request
	// - parameter collector: The MoustacheEvaluationOutputCollector which can be used to adjust the template output. For example a `defaultEncodingFunc` could be installed to change how outgoing values are encoded.
	override func valuesForResponse(context: MoustacheEvaluationContext, collector: MoustacheEvaluationOutputCollector) throws -> MoustacheEvaluationContext.MapType {
		
		// Call our super's implimentation.
		// If the user was properly validated then our inherited self.authenticatedUser property will not be nil.
		var values = try super.valuesForResponse(context, collector: collector)
		
		guard let user = self.authenticatedUser else {
			// Our parent class will have set the web response code to trigger authentication.
			return values
		}
		
		// Add keys to the dict
		values["title"] = "Perfect Project Template"
		values["firstName"] = user.firstName
		values["lastName"] = user.lastName
		
		// Return the values
		// These will be used to populate the template
		return values
	}
	
}
