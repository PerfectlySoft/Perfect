//
//  Perfect.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/5/15.
//
//

//import Foundation

public let SQLITE_DBS = "SQliteDBs/"
public let PERFECT_LIBRARIES = "PerfectLibraries/"

/// Provides access to various system level features for the process.
/// A static instance of this class is created at startup and all access to this object go through the `PerfectServer.staticPerfectServer` static property.
public class PerfectServer {
	
	public static let staticPerfectServer = PerfectServer()
	
	internal init() {
		
	}
	
	/// Performs any boot-strap level initialization such as creating databases or loading dynamic frameworks.
	/// Should only be called once befor starting FastCGI server
	public func initializeServices() {
		do {
			try SessionManager.initializeSessionsDatabase()
		} catch let e {
			LogManager.logMessage("Exception while initializing SQLite sessions database \(e)")
		}
		
		// !FIX! OS X only
		let dl = DynamicLoader()
		let baseDir = Dir(homeDir() + PERFECT_LIBRARIES)
		do {
			try baseDir.forEachEntry { (name: String) -> () in
				if name.hasSuffix(".framework") || name.hasSuffix(".framework/") {
					let fileName = baseDir.realPath() + "/" + name
					if dl.loadFramework(fileName) {
						print("Loaded "+name)
					} else {
						print("FAILED to load "+name)
					}
				}
			}
		} catch {
			//print("Exception \(e)")
		}
	}
	
	/// The directory containing all configuration and runtime data for the current server process.
	/// Not to be confused with the web server directory which only exists during an individual web request and in the mind of the web server itself.
	public func homeDir() -> String {
		return "./"
	}
}





