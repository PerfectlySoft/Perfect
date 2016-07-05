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

#if os(Linux)
	import SwiftGlibc
	import LinuxBridge
#else
	import Darwin
#endif

/// Placeholder functions for logging system
public protocol Logger {
	func info(message: String)
	func warning(message: String)
	func error(message: String)
	func critical(message: String)
	@noreturn
	func terminal(message: String)
}

public struct ConsoleLogger: Logger {
	public init(){}
	
	public func info(message: String) {
		print(message)
	}
	
	public func warning(message: String) {
		print(message)
	}
	
	public func error(message: String) {
		print(message)
	}
	
	public func critical(message: String) {
		print(message)
	}
	
	@noreturn
	public func terminal(message: String) {
		fatalError(message)
	}
}

public struct SysLogger: Logger {
	public init(){}
	
	func syslog(priority: Int32, message: String) {
		withVaList([message]) {
			vsyslog(priority, "%s", $0)
		}
	}
	
	public func info(message: String) {
		syslog(priority: LOG_INFO, message: message)
	}
	
	public func warning(message: String) {
		syslog(priority: LOG_WARNING, message: message)
	}
	
	public func error(message: String) {
		syslog(priority: LOG_ERR, message: message)
	}
	
	public func critical(message: String) {
		syslog(priority: LOG_CRIT, message: message)
	}
	
	@noreturn
	public func terminal(message: String) {
		syslog(priority: LOG_EMERG, message: message)
		fatalError(message)
	}
}

/// Placeholder functions for logging system
public struct Log {
	public static var logger: Logger = ConsoleLogger()
	
	public static func info(message: String) {
		Log.logger.info(message: message)
	}
	
	public static func warning(message: String) {
		Log.logger.warning(message: message)
	}
	
	public static func error(message: String) {
		Log.logger.error(message: message)
	}
	
	public static func critical(message: String) {
		Log.logger.critical(message: message)
	}
	
	@noreturn
	public static func terminal(message: String) {
		Log.logger.terminal(message: message)
	}
}
