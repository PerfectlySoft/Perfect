//
//  User-Server.swift
//  Authenticator
//
//  Created by Kyle Jessup on 2015-11-10.
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

// Server only extensions
extension User {
	
	convenience init?(email inEmail:String) {
		var id:Int?, fname:String?, lname:String?, email:String?, key:String?
		do {
			let sqlite = try SQLite(AUTH_DB_PATH)
			defer {
				sqlite.close()
			}
		
			try sqlite.forEachRow("SELECT u.id,u.fname,u.lname,u.email,a.key FROM users AS u JOIN auth AS a ON a.id_user = u.id WHERE u.email = :1", doBindings: {
				(stmt:SQLiteStmt) -> () in
				
				try stmt.bind(1, inEmail)
				
				}) {
					(stmt:SQLiteStmt, r:Int) -> () in
					
					(id, fname, lname, email, key) = (stmt.columnInt(0), stmt.columnText(1), stmt.columnText(2), stmt.columnText(3), stmt.columnText(4))
			}
		} catch {
			// just return nil
		}
		guard let _ = id else {
			return nil
		}
		self.init(id: id!, first: fname!, last: lname!, email: email!, authKey: key!)
	}
	
	static func create(first: String, last: String, email: String, password: String) -> User? {
		
		do {
			let sqlite = try SQLite(AUTH_DB_PATH)
			defer {
				sqlite.close()
			}
			
			try sqlite.execute("INSERT INTO users (fname,lname,email) VALUES (:1,:2,:3)") {
				(stmt:SQLiteStmt) -> () in
				
				try stmt.bind(1, first)
				try stmt.bind(2, last)
				try stmt.bind(3, email)
			}
			
			let lastId = sqlite.lastInsertRowID()
			let authKey = User.encodeRawPassword(email, password: password)
			
			try sqlite.execute("INSERT INTO auth (id_user,key) VALUES (:1,:2)") {
				(stmt:SQLiteStmt) -> () in
				
				try stmt.bind(1, lastId)
				try stmt.bind(2, authKey)
			}			
			
		} catch {
			
		}
		return User(email: email)
	}
	
	static func encodeRawPassword(email: String, password: String, realm: String = AUTH_REALM) -> String {
		let bytes = "\(email):\(realm):\(password)".md5
		return toHex(bytes)
	}
}
