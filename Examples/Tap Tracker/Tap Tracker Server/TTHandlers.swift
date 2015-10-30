//
//  TTHandlers.swift
//  Tap Tracker
//
//  Created by Kyle Jessup on 2015-10-23.
//
//

import PerfectLib

// Full path to the SQLite database in which we store our tracking data.
let TRACKER_DB_PATH = PerfectServer.staticPerfectServer.homeDir() + SQLITE_DBS + "TapTrackerDb"

// This is the function which all Perfect Server modules must expose.
// The system will load the module and call this function.
// In here, register any handlers or perform any one-time tasks.
public func PerfectServerModuleInit() {
	
	// Register our handler class with the PageHandlerRegistry.
	// The name "TTHandler", which we supply here, is used within a moustache template to associate the template with the handler.
	PageHandlerRegistry.addPageHandler("TTHandler") {
		
		// This closure is called in order to create the handler object.
		// It is called once for each relevant request.
		// The supplied WebResponse object can be used to tailor the return value.
		// However, all request processing should take place in the `valuesForResponse` function.
		(r:WebResponse) -> PageHandler in
		
		return TTHandler()
	}
	
	// Create our SQLite tracking database.
	do {
		let sqlite = try SQLite(TRACKER_DB_PATH)
		try sqlite.execute("CREATE TABLE IF NOT EXISTS taps (id INTEGER PRIMARY KEY, time REAL, lat REAL, long REAL)")
	} catch {
		print("Failure creating tracker database at " + TRACKER_DB_PATH)
	}
}

// Handler class
// When referenced in a moustache template, this class will be instantiated to handle the request
// and provide a set of values which will be used to complete the template.
class TTHandler: PageHandler { // all template handlers must inherit from PageHandler
	
	// This is the function which all handlers must impliment.
	// It is called by the system to allow the handler to return the set of values which will be used when populating the template.
	// - parameter context: The MoustacheEvaluationContext which provides access to the WebRequest containing all the information pertaining to the request
	// - parameter collector: The MoustacheEvaluationOutputCollector which can be used to adjust the template output. For example a `defaultEncodingFunc` could be installed to change how outgoing values are encoded.
	func valuesForResponse(context: MoustacheEvaluationContext, collector: MoustacheEvaluationOutputCollector) throws -> MoustacheEvaluationContext.MapType {
		
		// The dictionary which we will return
		var values = [String:Any]()
		
		print("TTHandler got request")
		
		// Grab the WebRequest
		if let request = context.webRequest {
			
			// Try to get the last tap instance from the database
			let sqlite = try SQLite(TRACKER_DB_PATH)
			defer {
				sqlite.close()
			}
			
			// Select most recent
			// If there are no existing taps, we'll just return the current one
			var gotTap = false
			
			try sqlite.forEachRow("SELECT time, lat, long FROM taps ORDER BY time DESC LIMIT 1") {
				(stmt:SQLiteStmt, i:Int) -> () in
				
				// We got a result row
				// Pull out the values and place them in the resulting values dictionary
				let time = stmt.columnDouble(0)
				let lat = stmt.columnDouble(1)
				let long = stmt.columnDouble(2)
				
				do {
					let timeStr = try ICU.formatDate(time, format: "yyyy-MM-d hh:mm aaa")
					
					let resultSets: [[String:Any]] = [["time": timeStr, "lat":lat, "long":long, "last":true]]
					values["resultSets"] = resultSets
				} catch { }
				
				gotTap = true
			}
			
			// If the user is posting a new tap for tracking purposes...
			if request.requestMethod() == "POST" {
				// Adding a new ta[ instance
				if let lat = request.param("lat"), let long = request.param("long") {
					
					let time = ICU.getNow()
					
					try sqlite.doWithTransaction {
						
						// Insert the new row
						try sqlite.execute("INSERT INTO taps (time,lat,long) VALUES (?,?,?)", doBindings: {
							(stmt:SQLiteStmt) -> () in
							
							try stmt.bind(1, time)
							try stmt.bind(2, lat)
							try stmt.bind(3, long)
						})
					}
					
					// As a fallback, for demo purposes, if there were no rows then just return the current values
					if !gotTap {
						let timeStr = try ICU.formatDate(time, format: "yyyy-MM-d hh:mm aaa")
						let resultSets: [[String:Any]] = [["time": timeStr, "lat":lat, "long":long, "last":true]]
						values["resultSets"] = resultSets
					}
				}
			}
		}
		// Return the values
		// These will be used to populate the template
		return values
	}
	
}


