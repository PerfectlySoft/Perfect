//
//  FAHandlers.swift
//  Fart Tracker
//
//  Created by Kyle Jessup on 2015-10-23.
//
//

import Foundation
import PerfectLib

let dbPath = PerfectServer.staticPerfectServer.homeDir() + SQLITE_DBS + "FartTrackerDb"

public func PerfectServerModuleInit() {
	FAHandler.registerHandler()
	
	do {
		let sqlite = try SQLite(dbPath)
		try sqlite.execute("CREATE TABLE IF NOT EXISTS farts (id INTEGER PRIMARY KEY, time REAL, lat REAL, long REAL)")
	} catch {
		print("Failure creating tracker database at " + dbPath)
	}
}

class FAHandler: PageHandler {
	func valuesForResponse(context: MoustacheEvaluationContext, collector: MoustacheEvaluationOutputCollector) throws -> MoustacheEvaluationContext.MapType {
		var values = [String:Any]()
		
		print("FAHandler got request")
		
		if let response = context.webResponse {
			let request = response.request
			
			// get the last fart instance
			let sqlite = try SQLite(dbPath)
			defer {
				sqlite.close()
			}
			
			try sqlite.forEachRow("SELECT time, lat, long FROM farts ORDER BY time DESC LIMIT 1") {
				(stmt:SQLiteStmt, i:Int) -> () in
				
				let time = stmt.columnDouble(0)
				let lat = stmt.columnDouble(1)
				let long = stmt.columnDouble(2)
				
				do {
					let timeStr = try ICU.formatDate(time, format: "yyyy-MM-d hh:mm aaa")
					
					let resultSets: [[String:Any]] = [["time": timeStr, "lat":lat, "long":long, "last":true]]
					values["resultSets"] = resultSets
				} catch { }
			}
			
			if request.requestMethod() == "POST" {
				// adding a new FartInstance
				if let lat = request.param("lat"), let long = request.param("long") {
					try sqlite.doWithTransaction {
						try sqlite.execute("INSERT INTO farts (time,lat,long) VALUES (?,?,?)", doBindings: {
							(stmt:SQLiteStmt) -> () in
							
							try stmt.bind(1, ICU.getNow())
							try stmt.bind(2, lat)
							try stmt.bind(3, long)
						})
					}
				}
			}
		}
		return values
	}
	
	static func registerHandler() {
		PageHandlerRegistry.addPageHandler("FAHandler") {
			(r:WebResponse) -> PageHandler in
			return FAHandler()
		}
	}
}


