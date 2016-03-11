//
//  User.swift
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


class User {
	
	let id: Int
	let firstName: String
	let lastName: String
	let email: String
	let authKey: String
	
	init(id: Int, first: String, last: String, email: String, authKey: String) {
		self.id = id
		self.firstName = first
		self.lastName = last
		self.email = email
		self.authKey = authKey
	}
}
