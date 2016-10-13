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
	func debug(message: String)
	func info(message: String)
	func warning(message: String)
	func error(message: String)
	func critical(message: String)
	func terminal(message: String)
}

public struct ConsoleLogger: Logger {
	public init(){}
	
	public func debug(message: String) {
		print("[DBG] " + message)
	}
	
	public func info(message: String) {
		print("[INFO] " + message)
	}
	
	public func warning(message: String) {
		print("[WARN] " + message)
	}
	
	public func error(message: String) {
		print("[ERR] " + message)
	}
	
	public func critical(message: String) {
		print("[CRIT] " + message)
	}
	
	public func terminal(message: String) {
		print("[TERM] " + message)
	}
}

public struct SysLogger: Logger {
	let consoleEcho = ConsoleLogger()
	public init(){}
	
	func syslog(priority: Int32, _ args: CVarArg...) {
		withVaList(args) {
			vsyslog(priority, "%s", $0)
		}
	}
	
	public func debug(message: String) {
		consoleEcho.debug(message: message)
		message.withCString {
			f in
			syslog(priority: LOG_DEBUG, f)
		}
	}
	
	public func info(message: String) {
		consoleEcho.info(message: message)
		message.withCString {
			f in
			syslog(priority: LOG_INFO, f)
		}
	}
	
	public func warning(message: String) {
		consoleEcho.warning(message: message)
		message.withCString {
			f in
			syslog(priority: LOG_WARNING, f)
		}
	}
	
	public func error(message: String) {
		consoleEcho.error(message: message)
		message.withCString {
			f in
			syslog(priority: LOG_ERR, f)
		}
	}
	
	public func critical(message: String) {
		consoleEcho.critical(message: message)
		message.withCString {
			f in
			syslog(priority: LOG_CRIT, f)
		}
	}
	
	public func terminal(message: String) {
		consoleEcho.terminal(message: message)
		message.withCString {
			f in
			syslog(priority: LOG_EMERG, f)
		}
	}
}

/// Placeholder functions for logging system
public struct Log {
	private init(){}
	
	public static var logger: Logger = ConsoleLogger()
	
	public static func debug(message: @autoclosure () -> String) {
//	#if DEBUG
		Log.logger.debug(message: message())
//	#endif
	}
	
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
	
	public static func terminal(message: String) -> Never  {
		Log.logger.terminal(message: message)
		fatalError(message)
	}
}
