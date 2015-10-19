//
//  main.swift
//  lassoserver
//
//  Created by Kyle Jessup on 7/6/15.
//
//

import Foundation
import PerfectLib

let ls = LassoServer.staticLassoServer
ls.initializeServices()

let fastCgiServer = FastCGIServer()

try fastCgiServer.start("./lasso.fastcgi.sock")

print("Good bye, World!")
