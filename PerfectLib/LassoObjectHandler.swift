//
//  LassoObjectHandler.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2015-08-18.
//
//

public class LassoObjectHandler: PageHandler {
	
	public var action: HandlerAction = .None
	public var params = [String:String]()
	
	public init() {}
	
	public func valuesForResponse(context: MoustacheEvaluationContext, collector: MoustacheEvaluationOutputCollector) throws -> MoustacheEvaluationContext.MapType {
		// determine the action
		let param = context.webResponse!.request.param(ACTION_PARAM_NAME) ?? HandlerAction.None.asString()
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
		return MoustacheEvaluationContext.MapType()
	}
}





