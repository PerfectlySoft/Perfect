//
//  main.swift
//  PerfectServer
//
//  Created by Kyle Jessup on 7/6/15.
//	Copyright (C) 2015 PerfectlySoft, Inc.
//
//     This program is free software: you can redistribute it and/or modify
//     it under the terms of the GNU Affero General Public License as published by
//     the Free Software Foundation, either version 3 of the License, or
//     (at your option) any later version.
//
//     This program is distributed in the hope that it will be useful,
//     but WITHOUT ANY WARRANTY; without even the implied warranty of
//     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//     GNU Affero General Public License for more details.
//
//     You should have received a copy of the GNU Affero General Public License
//     along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
