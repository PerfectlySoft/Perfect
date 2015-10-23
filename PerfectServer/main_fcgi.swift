//
//  main.swift
//  PerfectServer
//
//  Created by Kyle Jessup on 7/6/15.
//
//

import Foundation
import PerfectLib

func startServer() throws {

	let dir = String.fromCString(getcwd(nil, 0)) ?? ""
	print("Current working directory: \(dir)")

	let ls = PerfectServer.staticPerfectServer
	ls.initializeServices()

	let fastCgiServer = FastCGIServer()

	try fastCgiServer.start("./perfect.fastcgi.sock")

}
