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
	
	var webRoot = "./webroot/"
	var serverName = ""
	var localAddress = "0.0.0.0"
	var localPort = 8181
	var sslCert: String?
	var sslKey: String?
	var dhParams: String?
	
	var args = Process.arguments
	
	let validArgs = [
		"--sslcert": {
			args.removeFirst()
			sslCert = args.first!
		},
		"--sslkey": {
			args.removeFirst()
			sslKey = args.first!
		},
		"--dhparams": {
			args.removeFirst()
			dhParams = args.first!
		},
		"--port": {
			args.removeFirst()
			localPort = Int(args.first!) ?? 8181
		},
		"--address": {
			args.removeFirst()
			localAddress = args.first!
		},
		"--root": {
			args.removeFirst()
			webRoot = args.first!
		},
		"--name": {
			args.removeFirst()
			serverName = args.first!
        },
		"--libpath": {
            args.removeFirst()
            serverPerfectLibraries = args.first!
        },
		"--help": {
			print("Usage: \(Process.arguments.first!) [--port listen_port] [--address listen_address] [--name server_name] [--root root_path] [--sslcert cert_path --sslkey key_path] [--dhparams file_path] [--libpath lib_path]")
			exit(0)
		}]
	
	while args.count > 0 {
		if let closure = validArgs[args.first!.lowercaseString] {
			closure()
		}
		args.removeFirst()
	}
    
    ls.initializeServices()
    
	try Dir(webRoot).create()
	let httpServer = HTTPServer(documentRoot: webRoot)
	httpServer.serverName = serverName
	do {
		if sslCert != nil || sslKey != nil {
			
			if sslCert == nil || sslKey == nil {
				print("Error: if either --sslcert or --sslkey is provided then both --sslcert and --sslkey must be provided.")
				exit(-1)
			}
			
			if !File(sslCert!).exists() || !File(sslKey!).exists() {
				print("Error: --sslcert or --sslkey file did not exist.")
				exit(-1)
			}
			
			try httpServer.start(UInt16(localPort), sslCert: sslCert!, sslKey: sslKey!, dhParams: dhParams, bindAddress: localAddress)
			
		} else {
			try httpServer.start(UInt16(localPort), bindAddress: localAddress)
		}
	} catch PerfectError.NetworkError(let err, let msg) {
		print("Network error thrown: \(err) \(msg)")
	}
}






