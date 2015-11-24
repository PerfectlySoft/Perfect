//
//  PerfectObjectHandler.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2015-08-18.
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


public class PerfectObjectHandler: PageHandler {
	
	public var action: HandlerAction = .None
	public var params = [String:String]()
	
	public init() {}
	
	public func valuesForResponse(context: MustacheEvaluationContext, collector: MustacheEvaluationOutputCollector) throws -> MustacheEvaluationContext.MapType {
		// determine the action
		let param = context.webResponse!.request.param(actionParamName) ?? HandlerAction.None.asString()
		self.action = HandlerAction.fromString(param)
		// pull in the meaningful parameters
		if let rawParams = context.webResponse!.request.params() {
			// ignore "meta"
			for (n, v) in rawParams where !n.hasPrefix("_") && !n.hasPrefix("$") {
				self.params[n] = v
			}
		}
		context.webResponse!.replaceHeader("Content-type", value: "application/json")
		collector.defaultEncodingFunc = {
			(s:String) -> String in
			
			var outS = ""
			
			for char in s.characters.generate() {
				switch char {
				case "\\":
					outS.appendContentsOf("\\\\")
				case "\"":
					outS.appendContentsOf("\\\"")
				case "\n":
					outS.appendContentsOf("\\n")
				case "\r":
					outS.appendContentsOf("\\n")
				case "\t":
					outS.appendContentsOf("\\t")
				default:
					outS.append(char)
				}
			}
			
			return outS
		}
		return MustacheEvaluationContext.MapType()
	}
}





