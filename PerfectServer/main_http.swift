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

	try Dir(dir + "/webroot/").create()
	let httpServer = HTTPServer(documentRoot: dir + "/webroot/")
	try httpServer.start(8181)
}
