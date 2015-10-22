//
//  main.swift
//  PerfectServer
//
//  Created by Kyle Jessup on 7/6/15.
//
//

import Foundation
import PerfectLib

let ls = PerfectServer.staticPerfectServer
ls.initializeServices()

let fastCgiServer = FastCGIServer()

try fastCgiServer.start("./perfect.fastcgi.sock")

print("Good bye, World!")
