//
//  PerfectCRUDLogging.swift
//  PerfectCRUD
//
//  Created by Kyle Jessup on 2017-11-24.
//	Copyright (C) 2017 PerfectlySoft, Inc.
//
// ===----------------------------------------------------------------------===//
//
// This source file is part of the Perfect.org open source project
//
// Copyright (c) 2015 - 2017 PerfectlySoft Inc. and the Perfect project authors
// Licensed under Apache License v2.0
//
// See http://perfect.org/licensing.html for license information
//
// ===----------------------------------------------------------------------===//
//

import Foundation
import Dispatch

public struct CRUDSQLGenError: Error, CustomStringConvertible {
	public let description: String
	public init(_ msg: String) {
		description = msg
		CRUDLogging.log(.error, msg)
	}
}
public struct CRUDSQLExeError: Error, CustomStringConvertible {
	public let description: String
	public init(_ msg: String) {
		description = msg
		CRUDLogging.log(.error, msg)
	}
}

public enum CRUDLogDestination {
	case none
	case console
	case file(String)
	case custom((CRUDLogEvent) -> ())

	func handleEvent(_ event: CRUDLogEvent) {
		switch self {
		case .none:
			()
		case .console:
			print("\(event)")
		case .file(let name):
			let fm = FileManager()
			guard fm.isWritableFile(atPath: name) || fm.createFile(atPath: name, contents: nil, attributes: nil),
				let fileHandle = FileHandle(forWritingAtPath: name),
				let data = "\(event)\n".data(using: .utf8) else {
				print("[ERR] Unable to open file at \"\(name)\" to log event \(event)")
				return
			}
			defer {
				fileHandle.closeFile()
			}
			fileHandle.seekToEndOfFile()
			fileHandle.write(data)
		case .custom(let code):
			code(event)
		}
	}
}

public enum CRUDLogEventType: CustomStringConvertible {
	case info, warning, error, query
	public var description: String {
		switch self {
		case .info:
			return "INFO"
		case .warning:
			return "WARN"
		case .error:
			return "ERR"
		case .query:
			return "QUERY"
		}
	}
}

public struct CRUDLogEvent: CustomStringConvertible {
	public let time: Date
	public let type: CRUDLogEventType
	public let msg: String
	public var description: String {
		let formatter = DateFormatter()
		formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss ZZ"
		return "[\(formatter.string(from: time))] [\(type)] \(msg)"
	}
}

public struct CRUDLogging {
	private static var _queryLogDestinations: [CRUDLogDestination] = [.console]
	private static var _errorLogDestinations: [CRUDLogDestination] = [.console]
	private static var pendingEvents: [CRUDLogEvent] = []
	private static var loggingQueue: DispatchQueue = {
		let q = DispatchQueue(label: "CRUDLoggingQueue", qos: .background)
		scheduleLogCheck(q)
		return q
	}()
	private static func logCheckReschedulingInSerialQueue() {
		logCheckInSerialQueue()
		scheduleLogCheck(loggingQueue)
	}
	private static func logCheckInSerialQueue() {
		guard !pendingEvents.isEmpty else {
			return
		}
		let eventsToLog = pendingEvents
		pendingEvents = []
		eventsToLog.forEach {
			logEventInSerialQueue($0)
		}
	}
	private static func logEventInSerialQueue(_ event: CRUDLogEvent) {
		if case .query = event.type {
			_queryLogDestinations.forEach { $0.handleEvent(event) }
		} else {
			_errorLogDestinations.forEach { $0.handleEvent(event) }
		}
	}
	private static func scheduleLogCheck(_ queue: DispatchQueue) {
		queue.asyncAfter(deadline: .now() + 0.5, execute: logCheckReschedulingInSerialQueue)
	}
}

public extension CRUDLogging {
	static func flush() {
		loggingQueue.sync {
			logCheckInSerialQueue()
		}
	}
	static var queryLogDestinations: [CRUDLogDestination] {
		get {
			return loggingQueue.sync { return _queryLogDestinations }
		}
		set {
			loggingQueue.async { _queryLogDestinations = newValue }
		}
	}
	static var errorLogDestinations: [CRUDLogDestination] {
		get {
			return loggingQueue.sync { return _errorLogDestinations }
		}
		set {
			loggingQueue.async { _errorLogDestinations = newValue }
		}
	}
	static func log(_ type: CRUDLogEventType, _ msg: String) {
		let now = Date()
	#if DEBUG || Xcode
		loggingQueue.sync {
			pendingEvents.append(.init(time: now, type: type, msg: msg))
			logCheckInSerialQueue()
		}
	#else
		loggingQueue.async {
			pendingEvents.append(.init(time: now, type: type, msg: msg))
		}
	#endif
	}
}
