//
//  main.swift
//  PerfectServer
//
//  Created by Kyle Jessup on 7/6/15.
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

import PerfectLib
#if os(Linux)
	import SwiftGlibc
#else
	import Darwin
#endif

func startServer() throws {

	let ls = PerfectServer.staticPerfectServer

	var sockPath = "./perfect.fastcgi.sock"
	var args = Process.arguments
	
	let validArgs = [
		
		"--sockpath": {
			args.removeFirst()
			sockPath = args.first!
        },
		"--libpath": {
            args.removeFirst()
            serverPerfectLibraries = args.first!
        },
		"--help": {
			print("Usage: \(Process.arguments.first!) [--sockpath socket_path] [--libpath lib_path]")
			exit(0)
		}]
	
	while args.count > 0 {
		if let closure = validArgs[args.first!.lowercaseString] {
			closure()
		}
		args.removeFirst()
	}
    
    ls.initializeServices()
    
	let fastCgiServer = FastCGIServer()
	try fastCgiServer.start(sockPath)
}
