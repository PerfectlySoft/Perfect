//
//  Perfect.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/5/15.
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

/// Standard directory for server-side SQLite support databases
public let serverSQLiteDBs = "SQLiteDBs/"
/// Directory for server-size modules. Modules in this directory are loaded at server startup.
public var serverPerfectLibraries = "PerfectLibraries/"

/// Provides access to various system level features for the process.
/// A static instance of this class is created at startup and all access to this object go through the `PerfectServer.staticPerfectServer` static property.
public class PerfectServer {
	
	/// Provides access to the singleton PerfectServer instance.
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
		
		let dl = DynamicLoader()
        var baseDir : Dir
        if serverPerfectLibraries.hasPrefix("/") || serverPerfectLibraries.hasPrefix("~/") || serverPerfectLibraries.hasPrefix("./") {
            baseDir = Dir(serverPerfectLibraries)
        } else {
            baseDir = Dir(homeDir() + serverPerfectLibraries)
        }
        print("Load libs from: \(baseDir.realPath())");
		do {
			try baseDir.forEachEntry { (name: String) -> () in
				if name.hasSuffix(".framework") || name.hasSuffix(".framework/") {
					let fileName = baseDir.realPath() + "/" + name
					if dl.loadFramework(fileName) {
						print("Loaded "+name)
					} else {
						print("FAILED to load "+name)
					}
				} else if name.hasSuffix(".so") || name.hasSuffix(".dylib") {
					let fileName = baseDir.realPath() + "/" + name
					if dl.loadLibrary(fileName) {
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





