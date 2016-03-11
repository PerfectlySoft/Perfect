//
//  PerfectHandlers.swift
//  Authenticator
//
//  Created by Kyle Jessup on 2015-11-09.
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

// Full path to the SQLite database in which we store our data.
let AUTH_DB_PATH = PerfectServer.staticPerfectServer.homeDir() + serverSQLiteDBs + "AuthenticatorDb"

// HTTP authentication realm
let AUTH_REALM = "Authenticator Perfect Example"

// This is the function which all Perfect Server modules must expose.
// The system will load the module and call this function.
// In here, register any handlers or perform any one-time tasks.
public func PerfectServerModuleInit() {
	
	// Register our handler class with the PageHandlerRegistry.
	// The name "LoginHandler", which we supply here, is used within a mustache template to associate the template with the handler.
	PageHandlerRegistry.addPageHandler("LoginHandler") {
		
		// This closure is called in order to create the handler object.
		// It is called once for each relevant request.
		// The supplied WebResponse object can be used to tailor the return value.
		// However, all request processing should take place in the `valuesForResponse` function.
		(r:WebResponse) -> PageHandler in
		
		return LoginHandler()
	}
	
	// This handler takes the new user information and puts it in the database.
	PageHandlerRegistry.addPageHandler("RegistrationHandler") {
		return RegistrationHandler()
	}
	
	// This handler does literally nothing.
	PageHandlerRegistry.addPageHandler("NullHandler") {
		return NullHandler()
	}
	
	// For example, demo purposes - remove the existing database so that one has to register each time
	// Comment this little section out if you want the database to persist across runs.
	let oldFile = File(AUTH_DB_PATH)
	if oldFile.exists() {
		oldFile.delete()
	}
	
	// Create our SQLite tracking database.
	do {
		let sqlite = try SQLite(AUTH_DB_PATH)
		try sqlite.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, fname TEXT, lname TEXT, email TEXT)")
		try sqlite.execute("CREATE TABLE IF NOT EXISTS auth (id_user INTEGER, key TEXT)")
	} catch {
		print("Failure creating tracker database at " + AUTH_DB_PATH)
	}
}
