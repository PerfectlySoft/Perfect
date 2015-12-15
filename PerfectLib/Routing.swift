//
//  URLRoutingHandler.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2015-12-11.
//  Copyright © 2015 PerfectlySoft. All rights reserved.
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

/// Provides a namespace for Routing related objects.
public class Routing {
	
	private init() {}
	
	/// This is the main handler for the logic of the URL routing system.
	/// If must be enabled by calling `Routing.Handler.registerGlobally`
	public class Handler: PageHandler {
		
		/// Install the URL routing system.
		/// This is required if this system is to be utilized, otherwise it will not be available.
		static public func registerGlobally() {
			PageHandlerRegistry.addPageHandler { (_:WebResponse) -> PageHandler in
				return Routing.Handler()
			}
		}
		
		// This is the function which all handlers must impliment.
		// It is called by the system to allow the handler to return the set of values which will be used when populating the template.
		// - parameter context: The MustacheEvaluationContext which provides access to the WebRequest containing all the information pertaining to the request
		// - parameter collector: The MustacheEvaluationOutputCollector which can be used to adjust the template output. For example a `defaultEncodingFunc` could be installed to change how outgoing values are encoded.
		public func valuesForResponse(context: MustacheEvaluationContext, collector: MustacheEvaluationOutputCollector) throws -> MustacheEvaluationContext.MapType {
			let values = [String:Any]()
			
			return values
		}
		
	}
	
}

