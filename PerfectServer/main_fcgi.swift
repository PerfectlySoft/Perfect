//
//  main.swift
//  PerfectServer
//
//  Created by Kyle Jessup on 7/6/15.
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
