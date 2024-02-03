//
//  SQLite.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/14/15.
//	Copyright (C) 2015 PerfectlySoft, Inc.
//
// ===----------------------------------------------------------------------===//
//
// This source file is part of the Perfect.org open source project
//
// Copyright (c) 2015 - 2016 PerfectlySoft Inc. and the Perfect project authors
// Licensed under Apache License v2.0
//
// See http://perfect.org/licensing.html for license information
//
// ===----------------------------------------------------------------------===//
//

// Apple platforms have SQLite3 built-in. Linux? No.
#if os(Linux)
import PerfectCSQLite3
import SwiftGlibc
#else
import SQLite3
#endif

/// This enum type indicates an exception when dealing with a SQLite database
public struct SQLiteError: Error, CustomStringConvertible {
	public let code: Int
	public let description: String
	public init(code: Int, description: String) {
		self.code = code
		self.description = description
	}
}

/// A SQLite database
public class SQLite {

	let path: String
	var sqlite3 = OpaquePointer(bitPattern: 0)

    /// Create or open a SQLite database given a file path.
    ///
    /// - parameter path: String path to SQLite database
    /// - parameter readOnly: Optional, Bool flag for read/write setting, defaults to false
    /// - throws: SQLiteError
	public init(_ path: String, readOnly: Bool = false, busyTimeoutMillis: Int = 600000) throws {
		self.path = path
		let flags = readOnly ? SQLITE_OPEN_READONLY : SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE
		let res = sqlite3_open_v2(path, &self.sqlite3, flags, nil)
		if res != SQLITE_OK {
			throw SQLiteError(code: Int(res), description: "Unable to open database "+path)
		}
		sqlite3_busy_timeout(self.sqlite3, Int32(busyTimeoutMillis))
	}

	/// Close the SQLite database.
	public func close() {
		if self.sqlite3 != nil {
			sqlite3_close(self.sqlite3)
			self.sqlite3 = nil
		}
	}

	/// Close the SQLite database.
	public func close<T>(after: (SQLite) -> T) -> T {
		defer {
			close()
		}
		return after(self)
	}

	deinit {
		close()
	}

    /// Compile the SQL statement.
    ///
    /// - returns: A SQLiteStmt object representing the compiled statement.
	public func prepare(statement stat: String) throws -> SQLiteStmt {
		var statPtr = OpaquePointer(bitPattern: 0)
		let tail = UnsafeMutablePointer<UnsafePointer<Int8>?>(nil as OpaquePointer?)
		let res = sqlite3_prepare_v2(self.sqlite3, stat, Int32(stat.utf8.count), &statPtr, tail)
		try checkRes(res)
		return SQLiteStmt(db: self.sqlite3, stat: statPtr)
	}

    /// Returns the value of `sqlite3_last_insert_rowid`.
    ///
    /// - returns: Int last inserted row ID
	public func lastInsertRowID() -> Int {
		let res = sqlite3_last_insert_rowid(self.sqlite3)
		return Int(res)
	}

    /// Returns the value of `sqlite3_total_changes`.
    ///
    /// - returns: Int total changes
	public func totalChanges() -> Int {
		let res = sqlite3_total_changes(self.sqlite3)
		return Int(res)
	}

    /// Returns the value of `sqlite3_changes`.
    ///
    /// - returns: Int number of changes
	public func changes() -> Int {
		let res = sqlite3_changes(self.sqlite3)
		return Int(res)
	}

    /// Returns the value of `sqlite3_errcode`.
    ///
    /// - returns: Int error code
	public func errCode() -> Int {
		let res = sqlite3_errcode(self.sqlite3)
		return Int(res)
	}

    /// Returns the value of `sqlite3_errmsg`.
    ///
    /// - returns: String error message
	public func errMsg() -> String {
		return String(validatingUTF8: sqlite3_errmsg(self.sqlite3))!
	}

    /// Execute the given statement. Assumes there will be no parameter binding or resulting row data.
    ///
    /// - parameter statement: String statement to be executed
    /// - throws: ()
	public func execute(statement: String) throws {
		// swiftlint:disable unused_closure_parameter
		try forEachRow(statement: statement, doBindings: { (SQLiteStmt) throws -> () in () }) { _, _ in }
	}

    /// Execute the given statement. Calls the provided callback one time for parameter binding. Assumes there will be no resulting row data.
    ///
    /// - parameter statement: String statement to be executed
    /// - parameter doBindings: Block used for bindings
    /// - throws: ()
	public func execute(statement: String, doBindings: (SQLiteStmt) throws -> ()) throws {
		try forEachRow(statement: statement, doBindings: doBindings) { _, _ in }
	}

    /// Execute the given statement `count` times. Calls the provided callback on each execution for parameter binding. Assumes there will be no resulting row data.
    ///
    /// - parameter statement: String statement to be executed
    /// - parameter count: Int number of times to execute
    /// - parameter doBindings: Block to be executed for binding on each call
    /// - throws: ()
	public func execute(statement: String, count: Int, doBindings: (SQLiteStmt, Int) throws -> ()) throws {
		let stat = try prepare(statement: statement)
		defer { stat.finalize() }

		for idx in 1...count {
			try doBindings(stat, idx)
			try forEachRowBody(stat: stat) { _, _ in }
			_ = try stat.reset()
		}
	}

    /// Executes a BEGIN, calls the provided closure and executes a ROLLBACK if an exception occurs or a COMMIT if no exception occurs.
    ///
    /// - parameter closure: Block to be executed inside transaction
    /// - throws: ErrorType
	public func doWithTransaction(closure: () throws -> ()) throws {
		try execute(statement: "BEGIN")
		do {
			try closure()
			try execute(statement: "COMMIT")
		} catch let e {
			try execute(statement: "ROLLBACK")
			throw e
		}
	}

	/// Executes the statement and calls the closure for each resulting row.
    ///
    /// - parameter statement: String statement to be executed
    /// - parameter handleRow: Block to be executed for each row
    /// - throws: ()
	public func forEachRow(statement: String, handleRow: (SQLiteStmt, Int) throws -> ()) throws {
		let stat = try prepare(statement: statement)
		defer { stat.finalize() }

		try forEachRowBody(stat: stat, handleRow: handleRow)
	}

	/// Executes the statement, calling `doBindings` to handle parameter bindings and calling `handleRow` for each resulting row.
    ///
    /// - parameter statement: String statement to be executed
    /// - parameter doBindings: Block to perform bindings on statement
    /// - parameter handleRow:  Block to execute for each row
    /// - throws: ()
	public func forEachRow(statement: String, doBindings: (SQLiteStmt) throws -> (), handleRow: (SQLiteStmt, Int) throws -> ()) throws {
		let stat = try prepare(statement: statement)
		defer { stat.finalize() }

		try doBindings(stat)

		try forEachRowBody(stat: stat, handleRow: handleRow)
	}

	func forEachRowBody(stat: SQLiteStmt, handleRow: (SQLiteStmt, Int) throws -> ()) throws {
		var r = stat.step()
		guard r == SQLITE_ROW || r == SQLITE_DONE else {
			try checkRes(r)
			return
		}

		var rowNum = 1
		while r == SQLITE_ROW {
			try handleRow(stat, rowNum)
			rowNum += 1
			r = stat.step()
		}
	}

	func miniSleep(millis: Int) {
		var tv = timeval()
		tv.tv_sec = millis / 1000
	#if os(Linux)
		tv.tv_usec = Int((millis % 1000) * 1000)
	#else
		tv.tv_usec = Int32((millis % 1000) * 1000)
	#endif
		select(0, nil, nil, nil, &tv)
	}

	func checkRes(_ res: Int32) throws {
		try checkRes(Int(res))
	}

	func checkRes(_ res: Int) throws {
		if res != Int(SQLITE_OK) {
			throw SQLiteError(code: res, description: String(validatingUTF8: sqlite3_errmsg(self.sqlite3))!)
		}
	}
}

/// A compiled SQLite statement
public class SQLiteStmt {

	let db: OpaquePointer?
	var stat: OpaquePointer?
	// swiftlint:disable type_name
	typealias sqlite_destructor = @convention(c) (UnsafeMutableRawPointer?) -> Void

	init(db: OpaquePointer?, stat: OpaquePointer?) {
		self.db = db
		self.stat = stat
	}

	/// Close or "finalize" the statement.
	public func close() {
		finalize()
	}

	/// Close the statement.
	public func finalize() {
		if self.stat != nil {
			sqlite3_finalize(self.stat!)
			self.stat = nil
		}
	}

	/// Advance to the next row.
	public func step() -> Int32 {
		guard self.stat != nil else {
			return SQLITE_MISUSE
		}
		return sqlite3_step(self.stat!)
	}

	/// Bind the Double value to the indicated parameter.
    ///
    /// - parameter position: Int position of binding
    /// - parameter d: Double to be bound
    /// - throws: ()
	public func bind(position: Int, _ d: Double) throws {
		try checkRes(sqlite3_bind_double(self.stat!, Int32(position), d))
	}

	/// Bind the Int32 value to the indicated parameter.
    ///
    /// - parameter position: Int position of binding
    /// - parameter i: Int32 to be bound
    /// - throws: ()
	public func bind(position: Int, _ i: Int32) throws {
		try checkRes(sqlite3_bind_int(self.stat!, Int32(position), Int32(i)))
	}

	/// Bind the Int value to the indicated parameter.
    ///
    /// - parameter position: Int position of binding
    /// - parameter i: Int to be bound
    /// - throws: ()
	public func bind(position: Int, _ i: Int) throws {
		try checkRes(sqlite3_bind_int64(self.stat!, Int32(position), Int64(i)))
	}

	/// Bind the Int64 value to the indicated parameter.
    ///
    /// - parameter position: Int position of binding
    /// - parameter i: Int64 to be bound
    /// - throws: ()
	public func bind(position: Int, _ i: Int64) throws {
		try checkRes(sqlite3_bind_int64(self.stat!, Int32(position), i))
	}

	/// Bind the String value to the indicated parameter.
    ///
    /// - parameter position: Int position of binding
    /// - parameter s: String to be bound
    /// - throws: ()
	public func bind(position: Int, _ s: String) throws {
		try checkRes(sqlite3_bind_text(self.stat!, Int32(position), s, Int32(s.utf8.count), unsafeBitCast(OpaquePointer(bitPattern: -1), to: sqlite_destructor.self)))
	}

	/// Bind the [Int8] blob value to the indicated parameter.
    ///
    /// - parameter position: Int position of binding
    /// - parameter b: [Int8] blob to be bound
    /// - throws: ()
	public func bind(position: Int, _ b: [Int8]) throws {
		try checkRes(sqlite3_bind_blob(self.stat!, Int32(position), b, Int32(b.count), unsafeBitCast(OpaquePointer(bitPattern: -1), to: sqlite_destructor.self)))
	}

	/// Bind the [UInt8] blob value to the indicated parameter.
    ///
    /// - parameter position: Int position of binding
    /// - parameter b: [UInt8] blob to be bound
    /// - throws: ()
	public func bind(position: Int, _ b: [UInt8]) throws {
		try checkRes(sqlite3_bind_blob(self.stat!, Int32(position), b, Int32(b.count), unsafeBitCast(OpaquePointer(bitPattern: -1), to: sqlite_destructor.self)))
	}

	/// Bind a blob of `count` zero values to the indicated parameter.
    ///
    /// - parameter position: Int position of binding
    /// - parameter count: Int number of zero values in blob to be bound
    /// - throws: ()
	public func bindZeroBlob(position: Int, count: Int) throws {
		try checkRes(sqlite3_bind_zeroblob(self.stat!, Int32(position), Int32(count)))
	}

	/// Bind a null to the indicated parameter.
    ///
    /// - parameter position: Int position of binding
    /// - throws: ()
	public func bindNull(position: Int) throws {
		try checkRes(sqlite3_bind_null(self.stat!, Int32(position)))
	}

	/// Bind the Double value to the indicated parameter.
    ///
    /// - parameter name: String name of binding
    /// - parameter d: Double to be bound
    /// - throws: ()
	public func bind(name: String, _ d: Double) throws {
		try checkRes(sqlite3_bind_double(self.stat!, Int32(bindParameterIndex(name: name)), d))
	}

	/// Bind the Int32 value to the indicated parameter.
    ///
    /// - parameter name: String name of binding
    /// - parameter i: Int32 to be bound
    /// - throws: ()
	public func bind(name: String, _ i: Int32) throws {
		try checkRes(sqlite3_bind_int(self.stat!, Int32(bindParameterIndex(name: name)), Int32(i)))
	}

	/// Bind the Int value to the indicated parameter.
    ///
    /// - parameter name: String name of binding
    /// - parameter i: Int to be bound
    /// - throws: ()
	public func bind(name: String, _ i: Int) throws {
		try checkRes(sqlite3_bind_int64(self.stat!, Int32(bindParameterIndex(name: name)), Int64(i)))
	}

	/// Bind the Int64 value to the indicated parameter.
    ///
    /// - parameter name: String name of binding
    /// - parameter i: Int64 to be bound
    /// - throws: ()
	public func bind(name: String, _ i: Int64) throws {
		try checkRes(sqlite3_bind_int64(self.stat!, Int32(bindParameterIndex(name: name)), i))
	}

	/// Bind the String value to the indicated parameter.
    ///
    /// - parameter name: String name of binding
    /// - parameter s: String to be bound
    /// - throws: ()
	public func bind(name: String, _ s: String) throws {
		try checkRes(sqlite3_bind_text(self.stat!, Int32(bindParameterIndex(name: name)), s, Int32(s.utf8.count), unsafeBitCast(OpaquePointer(bitPattern: -1), to: sqlite_destructor.self)))
	}

	/// Bind the [Int8] blob value to the indicated parameter.
    ///
    /// - parameter name: String name of binding
    /// - parameter b: [Int8] blob to be bound
    /// - throws: ()
	public func bind(name: String, _ b: [Int8]) throws {
		try checkRes(sqlite3_bind_text(self.stat!, Int32(bindParameterIndex(name: name)), b, Int32(b.count), unsafeBitCast(OpaquePointer(bitPattern: -1), to: sqlite_destructor.self)))
	}

	/// Bind a blob of `count` zero values to the indicated parameter.
    ///
    /// - parameter name: String name of binding
    /// - parameter count: Int number of zero values in blob to be bound
    /// - throws: ()
	public func bindZeroBlob(name: String, count: Int) throws {
		try checkRes(sqlite3_bind_zeroblob(self.stat!, Int32(bindParameterIndex(name: name)), Int32(count)))
	}

	/// Bind a null to the indicated parameter.
    ///
    /// - parameter name: String name of binding
    /// - throws: ()
	public func bindNull(name: String) throws {
		try checkRes(sqlite3_bind_null(self.stat!, Int32(bindParameterIndex(name: name))))
	}

	/// Returns the index for the named parameter.
    ///
    /// - parameter name: String name of binding
    /// - throws: ()
    /// - returns: Int index of parameter
	public func bindParameterIndex(name: String) throws -> Int {
		let idx = sqlite3_bind_parameter_index(self.stat!, name)
		guard idx != 0 else {
			throw SQLiteError(code: Int(SQLITE_MISUSE), description: "The indicated bind parameter name was not found.")
		}
		return Int(idx)
	}

	/// Resets the SQL statement.
    ///
    /// - returns: Int result
	public func reset() throws -> Int {
		let res = sqlite3_reset(self.stat!)
		try checkRes(res)
		return Int(res)
	}

	/// Return the number of columns in mthe result set.
    ///
    /// - returns: Int count of columns in result set
	public func columnCount() -> Int {
		let res = sqlite3_column_count(self.stat!)
		return Int(res)
	}

	/// Returns the name for the indicated column.
    ///
    /// - parameter position: Int position of column
    /// - returns: String name of column
	public func columnName(position: Int) -> String {
		return String(validatingUTF8: sqlite3_column_name(self.stat!, Int32(position)))!
	}

	/// Returns the name of the declared type for the indicated column.
    ///
    /// - parameter position: Int position of column
    /// - returns: String name of declared type
	public func columnDeclType(position: Int) -> String {
		return String(validatingUTF8: sqlite3_column_decltype(self.stat!, Int32(position)))!
	}

	/// Returns the blob data for the indicated column.
    ///
    /// - parameter position: Int position of column
    /// - returns: [Int8] blob
	@available(*, deprecated, renamed:"columnIntBlob")
	public func columnBlob(position: Int) -> [Int8] {
		return columnIntBlob(position: position)
	}

	/// Returns the blob data for the indicated column.
	///
	/// - parameter position: Int position of column
	/// - returns: [I: BinaryInteger] blob
	public func columnIntBlob<I: BinaryInteger>(position: Int) -> [I] {
		let vp = sqlite3_column_blob(self.stat!, Int32(position))
		let vpLen = Int(sqlite3_column_bytes(self.stat!, Int32(position)))

		guard vpLen > 0 else {
			return []
		}

		var ret = [I]()
		if var bytesPtr = vp?.bindMemory(to: I.self, capacity: vpLen) {
			for _ in 0..<vpLen {
				ret.append(bytesPtr.pointee)
				bytesPtr = bytesPtr.successor()
			}
		}
		return ret
	}

	/// Returns the Double value for the indicated column.
    ///
    /// - parameter: Int position of column
    /// - returns: Double value for column
	public func columnDouble(position: Int) -> Double {
		return Double(sqlite3_column_double(self.stat!, Int32(position)))
	}

	/// Returns the Int value for the indicated column.
    ///
    /// - parameter: Int position of column
    /// - returns: Int value for column
	public func columnInt(position: Int) -> Int {
		return Int(sqlite3_column_int64(self.stat!, Int32(position)))
	}

	/// Returns the Int32 value for the indicated column.
    ///
    /// - parameter: Int position of column
    /// - returns: Int32 value for column
	public func columnInt32(position: Int) -> Int32 {
		return sqlite3_column_int(self.stat!, Int32(position))
	}

	/// Returns the Int64 value for the indicated column.
    ///
    /// - parameter: Int position of column
    /// - returns: Int64 value for column
	public func columnInt64(position: Int) -> Int64 {
		return sqlite3_column_int64(self.stat!, Int32(position))
	}

	/// Returns the String value for the indicated column.
    ///
    /// - parameter: Int position of column
    /// - returns: String value for column
	public func columnText(position: Int) -> String {
		if let res = sqlite3_column_text(self.stat!, Int32(position)) {
			return res.withMemoryRebound(to: Int8.self, capacity: 0) {
				String(validatingUTF8: $0) ?? ""
			}
		}
		return ""
	}

	/// Returns the type for the indicated column.
    ///
    /// - parameter: Int position of column
    /// - returns: Int32
	public func columnType(position: Int) -> Int32 {
		return sqlite3_column_type(self.stat!, Int32(position))
	}

	/// Test if the indicated column is an integer
	///
	/// - parameter: Int position of column
	/// - returns: Bool
	public func isInteger(position: Int) -> Bool {
		return SQLITE_INTEGER == columnType(position: position)
	}

	/// Test if the indicated column is a Float
	///
	/// - parameter: Int position of column
	/// - returns: Bool
	public func isFloat(position: Int) -> Bool {
		return SQLITE_FLOAT == columnType(position: position)
	}

	/// Test if the indicated column is Text
	///
	/// - parameter: Int position of column
	/// - returns: Bool
	public func isText(position: Int) -> Bool {
		return SQLITE_TEXT == columnType(position: position)
	}

	/// Test if the indicated column is a Blob
	///
	/// - parameter: Int position of column
	/// - returns: Bool
	public func isBlob(position: Int) -> Bool {
		return SQLITE_BLOB == columnType(position: position)
	}

	/// Test if the indicated column is NULL
	///
	/// - parameter: Int position of column
	/// - returns: Bool
	public func isNull(position: Int) -> Bool {
		return SQLITE_NULL == columnType(position: position)
	}

	func checkRes(_ res: Int32) throws {
		try checkRes(Int(res))
	}

	func checkRes(_ res: Int) throws {
		if res != Int(SQLITE_OK) {
			throw SQLiteError(code: res, description: String(validatingUTF8: sqlite3_errmsg(self.db!))!)
		}
	}

	deinit {
		finalize()
	}
}
