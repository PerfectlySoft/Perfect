//
//  FAHandlers.swift
//  Fart Tracker
//
//  Created by Kyle Jessup on 2015-10-23.
//
//

import Foundation
import PerfectLib

public func PerfectServerModuleInit() {
	FAHandler.registerHandler()
}

class FAHandler: PageHandler {
	func valuesForResponse(context: MoustacheEvaluationContext, collector: MoustacheEvaluationOutputCollector) throws -> MoustacheEvaluationContext.MapType {
		let values = [String:Any]()
		
		return values
	}
	
	static func registerHandler() {
		PageHandlerRegistry.addPageHandler("FAHandler") {
			(r:WebResponse) -> PageHandler in
			return FAHandler()
		}
	}
}
