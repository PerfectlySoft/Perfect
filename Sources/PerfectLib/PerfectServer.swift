//
//  Perfect.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/5/15.
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

import PerfectNet

#if os(Linux)
    import SwiftGlibc
#else
    import Darwin
#endif

/// Default directory for server-side modules. Modules in this directory are loaded at server startup.
public var serverPerfectLibraries = "PerfectLibraries/" // !FIX! or obsolete

/// Provides access to various system level features for the process.
/// A static instance of this class is created at startup and all access to this object go through the `PerfectServer.staticPerfectServer` static property.
public struct PerfectServer {
	
	/// Performs any boot-strap level initialization such as creating databases or loading dynamic frameworks.
	/// Should only be called once befor starting FastCGI server
	public static func initializeServices() {
		
		NetEvent.initialize()
		
		Routing.initialize()
		
		let dl = DynamicLoader()
        var baseDir : Dir
        if serverPerfectLibraries.begins(with: "/") || serverPerfectLibraries.begins(with: "~/") || serverPerfectLibraries.begins(with: "./") {
            baseDir = Dir(serverPerfectLibraries)
        } else {
            baseDir = Dir(PerfectServer.homeDir + serverPerfectLibraries)
        }
        Log.info(message: "Load libs from: \(baseDir.realPath())");
		do {
			try baseDir.forEachEntry { (name: String) -> () in
				if name.ends(with: ".framework") || name.ends(with: ".framework/") {
					let fileName = baseDir.realPath() + "/" + name
					if dl.loadFramework(atPath: fileName) {
						print("Loaded "+name)
					} else {
						print("FAILED to load "+name)
					}
				} else if name.ends(with: ".so") || name.ends(with: ".dylib") {
					let fileName = baseDir.realPath() + "/" + name
					if dl.loadLibrary(atPath: fileName) {
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
    public static var homeDir: String {
		return "./" // !FIX! or obsolete
	}
    
    /// Switch the current process to run with the permissions of the indicated user
    public static func switchTo(userName unam: String) throws {
        guard let pw = getpwnam(unam) else {
            try ThrowSystemError()
        }
        let gid = pw.pointee.pw_gid
        let uid = pw.pointee.pw_uid
        guard 0 == setgid(gid) else {
            try ThrowSystemError()
        }
        guard 0 == setuid(uid) else {
            try ThrowSystemError()
        }
    }
}

