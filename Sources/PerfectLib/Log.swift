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
	func debug(message: String, _ even: Bool)
	func info(message: String, _ even: Bool)
	func warning(message: String, _ even: Bool)
	func error(message: String, _ even: Bool)
	func critical(message: String, _ even: Bool)
	func terminal(message: String, _ even: Bool)
}

public struct ConsoleLogger: Logger {
	public init(){}
	
	public func debug(message: String, _ even: Bool) {
		print((even ? "[DBG]  " : "[DBG] ") + message)
	}
	
	public func info(message: String, _ even: Bool) {
		print((even ? "[INFO] " : "[INFO] ") + message)
	}
	
	public func warning(message: String, _ even: Bool) {
		print((even ? "[WARN] " : "[WARN] ") + message)
	}
	
	public func error(message: String, _ even: Bool) {
		print((even ? "[ERR]  " : "[ERR] ") + message)
	}
	
	public func critical(message: String, _ even: Bool) {
		print((even ? "[CRIT] " : "[CRIT] ") + message)
	}
	
	public func terminal(message: String, _ even: Bool) {
		print((even ? "[TERM] " : "[TERM] ") + message)
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
	
	public func debug(message: String, _ even: Bool) {
		consoleEcho.debug(message: message, even)
		message.withCString {
			f in
			syslog(priority: LOG_DEBUG, f)
		}
	}
	
	public func info(message: String, _ even: Bool) {
		consoleEcho.info(message: message, even)
		message.withCString {
			f in
			syslog(priority: LOG_INFO, f)
		}
	}
	
	public func warning(message: String, _ even: Bool) {
		consoleEcho.warning(message: message, even)
		message.withCString {
			f in
			syslog(priority: LOG_WARNING, f)
		}
	}
	
	public func error(message: String, _ even: Bool) {
		consoleEcho.error(message: message, even)
		message.withCString {
			f in
			syslog(priority: LOG_ERR, f)
		}
	}
	
	public func critical(message: String, _ even: Bool) {
		consoleEcho.critical(message: message, even)
		message.withCString {
			f in
			syslog(priority: LOG_CRIT, f)
		}
	}
	
	public func terminal(message: String, _ even: Bool) {
		consoleEcho.terminal(message: message, even)
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
	
	/// Whether or not to even off the log messages
	/// If set to true log messages will be inline with each other
	public static var even = false
	
	public static func debug(message: @autoclosure () -> String) {
//	#if DEBUG
		Log.logger.debug(message: message(), even)
//	#endif
	}
	
	public static func info(message: String, evenIdents: Bool = even) {
		Log.logger.info(message: message, evenIdents)
	}
	
	public static func warning(message: String, evenIdents: Bool = even) {
		Log.logger.warning(message: message, evenIdents)
	}
	
	public static func error(message: String, evenIdents: Bool = even) {
		Log.logger.error(message: message, evenIdents)
	}
	
	public static func critical(message: String, evenIdents: Bool = even) {
		Log.logger.critical(message: message, evenIdents)
	}
	
	public static func terminal(message: String, evenIdents: Bool = even) -> Never  {
		Log.logger.terminal(message: message, evenIdents)
		fatalError(message)
	}
}
