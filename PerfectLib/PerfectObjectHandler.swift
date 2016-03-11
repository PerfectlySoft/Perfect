//
//  PerfectObjectHandler.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2015-08-18.
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





