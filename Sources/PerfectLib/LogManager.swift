//
//  LogManager.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/21/15.
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

/// Placeholder functions for logging system
public struct Log {
	
	static func info(message message: String) {
		print(message)
	}
	
	static func warning(message message: String) {
		print(message)
	}
	
	static func error(message message: String) {
		print(message)
	}
	
	static func critical(message message: String) {
		print(message)
	}
	@noreturn
	static func terminal(message message: String) {
		fatalError(message)		
	}
}