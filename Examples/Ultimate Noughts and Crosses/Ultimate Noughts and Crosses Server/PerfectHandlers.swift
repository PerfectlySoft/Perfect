//
//  PerfectHandlers.swift
//  Ultimate Noughts and Crosses
//
//  Created by Kyle Jessup on 2015-11-12.
//  Copyright © 2015 PerfectlySoft. All rights reserved.
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
import Darwin

let GAME_DB_PATH = PerfectServer.staticPerfectServer.homeDir() + serverSQLiteDBs + "utictactoe"

// This is the function which all Perfect Server modules must expose.
// The system will load the module and call this function.
// In here, register any handlers or perform any one-time tasks.
public func PerfectServerModuleInit() {
	
	// Register our handler class with the PageHandlerRegistry.
	// The name "FAHandler", which we supply here, is used within a moustache template to associate the template with the handler.
	PageHandlerRegistry.addPageHandler("UNCHandler") {
		
		// This closure is called in order to create the handler object.
		// It is called once for each relevant request.
		// The supplied WebResponse object can be used to tailor the return value.
		// However, all request processing should take place in the `valuesForResponse` function.
		(r:WebResponse) -> PageHandler in
		
		return UNCHandler()
	}
	
	GameState().initializeDatabase()
}


