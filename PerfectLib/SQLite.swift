//
//  SQLite.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/14/15.
//
//

import Foundation
import SQLite3

/// This enum type indicates an exception when dealing with a SQLite database
public enum SQLiteError : ErrorType {
	case Error(code: Int, msg: String)
}

/// A SQLite database
public class SQLite : Closeable {

	let path: String
	var sqlite3: COpaquePointer
	
	public init(_ path: String) throws {
		self.path = path
		self.sqlite3 = COpaquePointer()
		let res = sqlite3_open(path, &self.sqlite3)
		if res != SQLITE_OK {
			throw SQLiteError.Error(code: Int(res), msg: "Unable to open database "+path)
		}
		
	}
	
	public func close() {
		sqlite3_close(self.sqlite3)
	}
	
	deinit {
		close()
	}
	
	public func prepare(stat: String) throws -> SQLiteStmt {
		var statPtr = COpaquePointer()
		let tail = UnsafeMutablePointer<UnsafePointer<Int8>>()
		let res = sqlite3_prepare_v2(self.sqlite3, stat, Int32(stat.utf8.count), &statPtr, tail)
		try checkRes(res)
		return SQLiteStmt(db: self.sqlite3, stat: statPtr)
	}
	
	public func lastInsertRowID() -> Int {
		let res = sqlite3_last_insert_rowid(self.sqlite3)
		return Int(res)
	}
	
	public func totalChanges() -> Int {
		let res = sqlite3_total_changes(self.sqlite3)
		return Int(res)
	}
	
	public func changes() -> Int {
		let res = sqlite3_changes(self.sqlite3)
		return Int(res)
	}
	
	public func errCode() -> Int {
		let res = sqlite3_errcode(self.sqlite3)
		return Int(res)
	}
	
	public func errMsg() -> String {
		return String.fromCString(sqlite3_errmsg(self.sqlite3))!
	}
	
	public func execute(statement: String) throws {
		try forEachRow(statement, doBindings: { (SQLiteStmt) throws -> () in () }) {
			(SQLiteStmt) -> () in
			// nothing
		}
	}
	
	public func execute(statement: String, doBindings: (SQLiteStmt) throws -> ()) throws {
		try forEachRow(statement, doBindings: doBindings) {
			(SQLiteStmt) -> () in
			// nothing
		}
	}
	
	public func execute(statement: String, count: Int, doBindings: (SQLiteStmt, Int) throws -> ()) throws {
		let stat = try prepare(statement)
		defer { stat.finalize() }
		
		for idx in 1...count {
			try doBindings(stat, idx)
			try forEachRowBody(stat) {
				(SQLiteStmt) -> () in
				// nothing
			}
			try stat.reset()
		}
	}
	
	public func doWithTransaction(closure: () throws -> ()) throws {
		try execute("BEGIN")
		do {
			try closure()
			try execute("COMMIT")
		} catch let e {
			try execute("ROLLBACK")
			throw e
		}
	}
	
	public func forEachRow(statement: String, handleRow: (SQLiteStmt, Int) -> ()) throws {
		let stat = try prepare(statement)
		defer { stat.finalize() }
		
		try forEachRowBody(stat, handleRow: handleRow)
	}
	
	public func forEachRow(statement: String, doBindings: (SQLiteStmt) throws -> (), handleRow: (SQLiteStmt, Int) -> ()) throws {
		let stat = try prepare(statement)
		defer { stat.finalize() }
		
		try doBindings(stat)
		
		try forEachRowBody(stat, handleRow: handleRow)
	}
	
	func forEachRowBody(stat: SQLiteStmt, handleRow: (SQLiteStmt, Int) -> ()) throws {
		var r = stat.step()
		if r == SQLITE_LOCKED || r == SQLITE_BUSY {
			miniSleep(1)
			if r == SQLITE_LOCKED {
				try stat.reset()
			}
			r = stat.step()
			var times = 1000000
			while (r == SQLITE_LOCKED || r == SQLITE_BUSY) && times > 0 {
				if r == SQLITE_LOCKED {
					try stat.reset()
				}
				r = stat.step()
				times -= 1
			}
			guard r != SQLITE_LOCKED && r != SQLITE_BUSY else {
				try checkRes(r)
				return
			}
		}
		var rowNum = 1
		while r == SQLITE_ROW {
			handleRow(stat, rowNum++)
			r = stat.step()
		}
	}
	
	func miniSleep(millis: Int) {
		var tv = timeval()
		tv.tv_sec = millis / 1000
		tv.tv_usec = __darwin_suseconds_t((millis % 1000) * 1000)
		select(0, nil, nil, nil, &tv)
	}
	
	func checkRes(res: Int32) throws {
		try checkRes(Int(res))
	}
	
	func checkRes(res: Int) throws {
		if res != Int(SQLITE_OK) {
			throw SQLiteError.Error(code: res, msg: String.fromCString(sqlite3_errmsg(self.sqlite3))!)
		}
	}
}

/// A compiled SQLite statement
public class SQLiteStmt : Closeable {
	
	let db: COpaquePointer
	var stat: COpaquePointer?
	
	typealias sqlite_destructor = @convention(c) (UnsafeMutablePointer<Void>) -> Void
	
	init(db: COpaquePointer, stat: COpaquePointer) {
		self.db = db
		self.stat = stat
	}
	
	public func close() {
		finalize()
	}
	
	public func finalize() {
		if self.stat != nil {
			sqlite3_finalize(self.stat!)
			self.stat = nil
		}
	}
	
	public func step() -> Int32 {
		guard self.stat != nil else {
			return SQLITE_MISUSE
		}
		return sqlite3_step(self.stat!)
	}
	
	public func bind(position: Int, _ d: Double) throws {
		try checkRes(sqlite3_bind_double(self.stat!, Int32(position), d))
	}
	
	public func bind(position: Int, _ i: Int32) throws {
		try checkRes(sqlite3_bind_int(self.stat!, Int32(position), Int32(i)))
	}
	
	public func bind(position: Int, _ i: Int) throws {
		try checkRes(sqlite3_bind_int64(self.stat!, Int32(position), Int64(i)))
	}
	
	public func bind(position: Int, _ i: Int64) throws {
		try checkRes(sqlite3_bind_int64(self.stat!, Int32(position), i))
	}
	
	public func bind(position: Int, _ s: String) throws {
		try checkRes(sqlite3_bind_text(self.stat!, Int32(position), s, Int32(s.utf8.count), unsafeBitCast(COpaquePointer(bitPattern: -1), sqlite_destructor.self)))
	}
	
	public func bind(position: Int, _ b: [Int8]) throws {
		try checkRes(sqlite3_bind_blob(self.stat!, Int32(position), b, Int32(b.count), unsafeBitCast(COpaquePointer(bitPattern: -1), sqlite_destructor.self)))
	}
	
	public func bind(position: Int, _ b: [UInt8]) throws {
		try checkRes(sqlite3_bind_blob(self.stat!, Int32(position), b, Int32(b.count), unsafeBitCast(COpaquePointer(bitPattern: -1), sqlite_destructor.self)))
	}
	
	public func bindZeroBlob(position: Int, count: Int) throws {
		try checkRes(sqlite3_bind_zeroblob(self.stat!, Int32(position), Int32(count)))
	}
	
	public func bindNull(position: Int) throws {
		try checkRes(sqlite3_bind_null(self.stat!, Int32(position)))
	}
	
	public func bind(name: String, _ d: Double) throws {
		try checkRes(sqlite3_bind_double(self.stat!, Int32(bindParameterIndex(name)), d))
	}
	
	public func bind(name: String, _ i: Int32) throws {
		try checkRes(sqlite3_bind_int(self.stat!, Int32(bindParameterIndex(name)), Int32(i)))
	}
	
	public func bind(name: String, _ i: Int) throws {
		try checkRes(sqlite3_bind_int64(self.stat!, Int32(bindParameterIndex(name)), Int64(i)))
	}
	
	public func bind(name: String, _ i: Int64) throws {
		try checkRes(sqlite3_bind_int64(self.stat!, Int32(bindParameterIndex(name)), i))
	}
	
	public func bind(name: String, _ s: String) throws {
		try checkRes(sqlite3_bind_text(self.stat!, Int32(bindParameterIndex(name)), s, Int32(s.utf8.count), unsafeBitCast(COpaquePointer(bitPattern: -1), sqlite_destructor.self)))
	}
	
	public func bind(name: String, _ b: [Int8]) throws {
		try checkRes(sqlite3_bind_text(self.stat!, Int32(bindParameterIndex(name)), b, Int32(b.count), unsafeBitCast(COpaquePointer(bitPattern: -1), sqlite_destructor.self)))
	}
	
	public func bindZeroBlob(name: String, count: Int) throws {
		try checkRes(sqlite3_bind_zeroblob(self.stat!, Int32(bindParameterIndex(name)), Int32(count)))
	}
	
	public func bindNull(name: String) throws {
		try checkRes(sqlite3_bind_null(self.stat!, Int32(bindParameterIndex(name))))
	}
	
	public func bindParameterIndex(name: String) throws -> Int {
		let idx = sqlite3_bind_parameter_index(self.stat!, name)
		guard idx != 0 else {
			throw SQLiteError.Error(code: Int(SQLITE_MISUSE), msg: "The indicated bind parameter name was not found.")
		}
		return Int(idx)
	}
	
	public func reset() throws -> Int {
		let res = sqlite3_reset(self.stat!)
		try checkRes(res)
		return Int(res)
	}
	
	public func columnCount() -> Int {
		let res = sqlite3_column_count(self.stat!)
		return Int(res)
	}
	
	public func columnName(position: Int) -> String {
		return String.fromCString(sqlite3_column_name(self.stat!, Int32(position)))!
	}
	
	public func columnDeclType(position: Int) -> String {
		return String.fromCString(sqlite3_column_decltype(self.stat!, Int32(position)))!
	}
	
	public func columnBlob(position: Int) -> [Int8] {
		let vp = sqlite3_column_blob(self.stat!, Int32(position))
		let vpLen = sqlite3_column_bytes(self.stat!, Int32(position))
		
		guard vpLen > 0 else {
			return [Int8]()
		}
		
		var bytesPtr = UnsafePointer<Int8>(vp)
		var ret = [Int8]()
		for _ in 0..<vpLen {
			ret.append(bytesPtr.memory)
			bytesPtr = bytesPtr.successor()
		}
		return ret
	}
	
	public func columnDouble(position: Int) -> Double {
		return Double(sqlite3_column_double(self.stat!, Int32(position)))
	}
	
	public func columnInt(position: Int) -> Int {
		return Int(sqlite3_column_int64(self.stat!, Int32(position)))
	}
	
	public func columnInt32(position: Int) -> Int32 {
		return sqlite3_column_int(self.stat!, Int32(position))
	}
	
	public func columnInt64(position: Int) -> Int64 {
		return sqlite3_column_int64(self.stat!, Int32(position))
	}
	
	public func columnText(position: Int) -> String {
		let res = sqlite3_column_text(self.stat!, Int32(position))
		if res != nil {
			return String.fromCString(UnsafePointer<CChar>(res))!
		}
		return ""
	}
	
	public func columnType(position: Int) -> Int32 {
		return sqlite3_column_type(self.stat!, Int32(position))
	}
	
	func checkRes(res: Int32) throws {
		try checkRes(Int(res))
	}
	
	func checkRes(res: Int) throws {
		if res != Int(SQLITE_OK) {
			throw SQLiteError.Error(code: res, msg: String.fromCString(sqlite3_errmsg(self.db))!)
		}
	}
	
	deinit {
		finalize()
	}
}









