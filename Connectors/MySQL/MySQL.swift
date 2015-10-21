//
//  MySQL.swift
//  MySQL
//
//  Created by Kyle Jessup on 2015-10-01.
//  Copyright © 2015 TreeFrog. All rights reserved.
//

import Foundation
import PerfectLib
import libmysqlclient

public enum MySQLOpt {
	case MYSQL_OPT_CONNECT_TIMEOUT, MYSQL_OPT_COMPRESS, MYSQL_OPT_NAMED_PIPE,
		MYSQL_INIT_COMMAND, MYSQL_READ_DEFAULT_FILE, MYSQL_READ_DEFAULT_GROUP,
		MYSQL_SET_CHARSET_DIR, MYSQL_SET_CHARSET_NAME, MYSQL_OPT_LOCAL_INFILE,
		MYSQL_OPT_PROTOCOL, MYSQL_SHARED_MEMORY_BASE_NAME, MYSQL_OPT_READ_TIMEOUT,
		MYSQL_OPT_WRITE_TIMEOUT, MYSQL_OPT_USE_RESULT,
		MYSQL_OPT_USE_REMOTE_CONNECTION, MYSQL_OPT_USE_EMBEDDED_CONNECTION,
		MYSQL_OPT_GUESS_CONNECTION, MYSQL_SET_CLIENT_IP, MYSQL_SECURE_AUTH,
		MYSQL_REPORT_DATA_TRUNCATION, MYSQL_OPT_RECONNECT,
		MYSQL_OPT_SSL_VERIFY_SERVER_CERT, MYSQL_PLUGIN_DIR, MYSQL_DEFAULT_AUTH,
		MYSQL_OPT_BIND,
		MYSQL_OPT_SSL_KEY, MYSQL_OPT_SSL_CERT,
		MYSQL_OPT_SSL_CA, MYSQL_OPT_SSL_CAPATH, MYSQL_OPT_SSL_CIPHER,
		MYSQL_OPT_SSL_CRL, MYSQL_OPT_SSL_CRLPATH,
		MYSQL_OPT_CONNECT_ATTR_RESET, MYSQL_OPT_CONNECT_ATTR_ADD,
		MYSQL_OPT_CONNECT_ATTR_DELETE,
		MYSQL_SERVER_PUBLIC_KEY,
		MYSQL_ENABLE_CLEARTEXT_PLUGIN,
		MYSQL_OPT_CAN_HANDLE_EXPIRED_PASSWORDS
}

public class MySQL {
	
	static var dispatchOnce: dispatch_once_t = 0
	
	var ptr: UnsafeMutablePointer<MYSQL>
	
	public static func clientInfo() -> String {
		return String.fromCString(mysql_get_client_info()) ?? ""
	}
	
	public init() {
		
		dispatch_once(&MySQL.dispatchOnce) {
			mysql_server_init(0, nil, nil)
		}
		
		self.ptr = mysql_init(nil)
	}
	
	deinit {
		self.close()
	}
	
	public func close() {
		if self.ptr != nil {
			mysql_close(self.ptr)
			self.ptr = nil
		}
	}
	
	public func errorCode() -> UInt32 {
		return mysql_errno(self.ptr)
	}
	
	public func errorMessage() -> String {
		return String.fromCString(mysql_error(self.ptr)) ?? ""
	}
	
	// returns an allocated buffer holding the string's contents and the full size in bytes which was allocated
	// An empty (but not nil) string would have a count of 1
	static func convertString(s: String?) -> (UnsafeMutablePointer<Int8>, Int) {
		var ret: (UnsafeMutablePointer<Int8>, Int) = (UnsafeMutablePointer<Int8>(), 0)
		guard let notNilString = s else {
			return ret
		}
		notNilString.withCString { p in
			var c = 0
			while p[c] != 0 {
				c += 1
			}
			c += 1
			let alloced = UnsafeMutablePointer<Int8>.alloc(c)
			alloced.initialize(0)
			for i in 0..<c {
				alloced[i] = p[i]
			}
			alloced[c-1] = 0
			ret = (alloced, c)
		}
		return ret
	}
	
	func cleanConvertedString(pair: (UnsafeMutablePointer<Int8>, Int)) {
		if pair.1 > 0 {
			pair.0.destroy()
			pair.0.dealloc(pair.1)
		}
	}
	
	public func connect(host: String? = nil, user: String? = nil, password: String? = nil, db: String? = nil, port: UInt32 = 0, socket: String? = nil, flag: UInt = 0) -> Bool {
		if self.ptr == nil {
			self.ptr = mysql_init(nil)
		}
		
		let hostOrBlank = MySQL.convertString(host)
		let userOrBlank = MySQL.convertString(user)
		let passwordOrBlank = MySQL.convertString(password)
		let dbOrBlank = MySQL.convertString(db)
		let socketOrBlank = MySQL.convertString(socket)

		defer {
			self.cleanConvertedString(hostOrBlank)
			self.cleanConvertedString(userOrBlank)
			self.cleanConvertedString(passwordOrBlank)
			self.cleanConvertedString(dbOrBlank)
			self.cleanConvertedString(socketOrBlank)
		}
		
		let check = mysql_real_connect(self.ptr, hostOrBlank.0, userOrBlank.0, passwordOrBlank.0, dbOrBlank.0, port, socketOrBlank.0, flag)
		return check != nil && check == self.ptr
	}
	
	public func selectDatabase(named: String) -> Bool {
		let r = mysql_select_db(self.ptr, named)
		return r == 0
	}
	
	public func listTables(wild: String? = nil) -> [String] {
		var result = [String]()
		let res = (wild == nil ? mysql_list_tables(self.ptr, nil) : mysql_list_tables(self.ptr, wild!))
		if res != nil {
			var row = mysql_fetch_row(res)
			while row != nil {
				result.append(String.fromCString(row[0]) ?? "")
				row = mysql_fetch_row(res)
			}
			mysql_free_result(res)
		}
		return result
	}
	
	public func listDatabases(wild: String? = nil) -> [String] {
		var result = [String]()
		let res = wild == nil ? mysql_list_dbs(self.ptr, nil) : mysql_list_dbs(self.ptr, wild!)
		if res != nil {
			var row = mysql_fetch_row(res)
			while row != nil {
				result.append(String.fromCString(row[0]) ?? "")
				row = mysql_fetch_row(res)
			}
			mysql_free_result(res)
		}
		return result
	}
	
	public func commit() -> Bool {
		let r = mysql_commit(self.ptr)
		return r == 1
	}
	
	public func rollback() -> Bool {
		let r = mysql_rollback(self.ptr)
		return r == 1
	}
	
	public func moreResults() -> Bool {
		let r = mysql_more_results(self.ptr)
		return r == 1
	}
	
	public func nextResult() -> Int {
		let r = mysql_next_result(self.ptr)
		return Int(r)
	}
	
	public func query(stmt: String) -> Bool {
		let r = mysql_real_query(self.ptr, stmt, UInt(stmt.utf8.count))
		return r == 0
	}
	
	public func storeResults() -> MySQL.Results {
		return MySQL.Results(mysql_store_result(self.ptr))
	}
	
	func exposedOptionToMySQLOption(o: MySQLOpt) -> mysql_option {
		switch o {
		case MySQLOpt.MYSQL_OPT_CONNECT_TIMEOUT:
			return MYSQL_OPT_CONNECT_TIMEOUT
		case MySQLOpt.MYSQL_OPT_COMPRESS:
			return MYSQL_OPT_COMPRESS
		case MySQLOpt.MYSQL_OPT_NAMED_PIPE:
			return MYSQL_OPT_NAMED_PIPE
		case MySQLOpt.MYSQL_INIT_COMMAND:
			return MYSQL_INIT_COMMAND
		case MySQLOpt.MYSQL_READ_DEFAULT_FILE:
			return MYSQL_READ_DEFAULT_FILE
		case MySQLOpt.MYSQL_READ_DEFAULT_GROUP:
			return MYSQL_READ_DEFAULT_GROUP
		case MySQLOpt.MYSQL_SET_CHARSET_DIR:
			return MYSQL_SET_CHARSET_DIR
		case MySQLOpt.MYSQL_SET_CHARSET_NAME:
			return MYSQL_SET_CHARSET_NAME
		case MySQLOpt.MYSQL_OPT_LOCAL_INFILE:
			return MYSQL_OPT_LOCAL_INFILE
		case MySQLOpt.MYSQL_OPT_PROTOCOL:
			return MYSQL_OPT_PROTOCOL
		case MySQLOpt.MYSQL_SHARED_MEMORY_BASE_NAME:
			return MYSQL_SHARED_MEMORY_BASE_NAME
		case MySQLOpt.MYSQL_OPT_READ_TIMEOUT:
			return MYSQL_OPT_READ_TIMEOUT
		case MySQLOpt.MYSQL_OPT_WRITE_TIMEOUT:
			return MYSQL_OPT_WRITE_TIMEOUT
		case MySQLOpt.MYSQL_OPT_USE_RESULT:
			return MYSQL_OPT_USE_RESULT
		case MySQLOpt.MYSQL_OPT_USE_REMOTE_CONNECTION:
			return MYSQL_OPT_USE_REMOTE_CONNECTION
		case MySQLOpt.MYSQL_OPT_USE_EMBEDDED_CONNECTION:
			return MYSQL_OPT_USE_EMBEDDED_CONNECTION
		case MySQLOpt.MYSQL_OPT_GUESS_CONNECTION:
			return MYSQL_OPT_GUESS_CONNECTION
		case MySQLOpt.MYSQL_SET_CLIENT_IP:
			return MYSQL_SET_CLIENT_IP
		case MySQLOpt.MYSQL_SECURE_AUTH:
			return MYSQL_SECURE_AUTH
		case MySQLOpt.MYSQL_REPORT_DATA_TRUNCATION:
			return MYSQL_REPORT_DATA_TRUNCATION
		case MySQLOpt.MYSQL_OPT_RECONNECT:
			return MYSQL_OPT_RECONNECT
		case MySQLOpt.MYSQL_OPT_SSL_VERIFY_SERVER_CERT:
			return MYSQL_OPT_SSL_VERIFY_SERVER_CERT
		case MySQLOpt.MYSQL_PLUGIN_DIR:
			return MYSQL_PLUGIN_DIR
		case MySQLOpt.MYSQL_DEFAULT_AUTH:
			return MYSQL_DEFAULT_AUTH
		case MySQLOpt.MYSQL_OPT_BIND:
			return MYSQL_OPT_BIND
		case MySQLOpt.MYSQL_OPT_SSL_KEY:
			return MYSQL_OPT_SSL_KEY
		case MySQLOpt.MYSQL_OPT_SSL_CERT:
			return MYSQL_OPT_SSL_CERT
		case MySQLOpt.MYSQL_OPT_SSL_CA:
			return MYSQL_OPT_SSL_CA
		case MySQLOpt.MYSQL_OPT_SSL_CAPATH:
			return MYSQL_OPT_SSL_CAPATH
		case MySQLOpt.MYSQL_OPT_SSL_CIPHER:
			return MYSQL_OPT_SSL_CIPHER
		case MySQLOpt.MYSQL_OPT_SSL_CRL:
			return MYSQL_OPT_SSL_CRL
		case MySQLOpt.MYSQL_OPT_SSL_CRLPATH:
			return MYSQL_OPT_SSL_CRLPATH
		case MySQLOpt.MYSQL_OPT_CONNECT_ATTR_RESET:
			return MYSQL_OPT_CONNECT_ATTR_RESET
		case MySQLOpt.MYSQL_OPT_CONNECT_ATTR_ADD:
			return MYSQL_OPT_CONNECT_ATTR_ADD
		case MySQLOpt.MYSQL_OPT_CONNECT_ATTR_DELETE:
			return MYSQL_OPT_CONNECT_ATTR_DELETE
		case MySQLOpt.MYSQL_SERVER_PUBLIC_KEY:
			return MYSQL_SERVER_PUBLIC_KEY
		case MySQLOpt.MYSQL_ENABLE_CLEARTEXT_PLUGIN:
			return MYSQL_ENABLE_CLEARTEXT_PLUGIN
		case MySQLOpt.MYSQL_OPT_CAN_HANDLE_EXPIRED_PASSWORDS:
			return MYSQL_OPT_CAN_HANDLE_EXPIRED_PASSWORDS
		}
	}
	
	public func setOption(option: MySQLOpt) -> Bool {
		return mysql_options(self.ptr, exposedOptionToMySQLOption(option), nil) == 0
	}
	
	public func setOption(option: MySQLOpt, _ b: Bool) -> Bool {
		var myB = my_bool(b ? 1 : 0)
		return mysql_options(self.ptr, exposedOptionToMySQLOption(option), &myB) == 0
	}
	
	public func setOption(option: MySQLOpt, _ i: Int) -> Bool {
		var myI = UInt32(i)
		return mysql_options(self.ptr, exposedOptionToMySQLOption(option), &myI) == 0
	}
	
	public func setOption(option: MySQLOpt, _ s: String) -> Bool {
		var b = false
		s.withCString { p in
			b = mysql_options(self.ptr, exposedOptionToMySQLOption(option), p) == 0
		}
		return b
	}
	
	public class Results: GeneratorType {
		var ptr: UnsafeMutablePointer<MYSQL_RES>
		
		public typealias Element = [String]
		
		init(_ ptr: UnsafeMutablePointer<MYSQL_RES>) {
			self.ptr = ptr
		}
		
		deinit {
			self.close()
		}
		
		public func close() {
			if self.ptr != nil {
				mysql_free_result(self.ptr)
				self.ptr = nil
			}
		}
		
		public func dataSeek(offset: UInt) {
			mysql_data_seek(self.ptr, my_ulonglong(offset))
		}
		
		public func numRows() -> Int {
			return Int(mysql_num_rows(self.ptr))
		}
		
		public func numFields() -> Int {
			return Int(mysql_num_fields(self.ptr))
		}
		
		public func next() -> Element? {
			let row = mysql_fetch_row(self.ptr)
			guard row != nil else {
				return nil
			}
			
			let lengths = mysql_fetch_lengths(self.ptr)
			var ret = [String]()
			
			for fieldIdx in 0..<self.numFields() {
				let len = Int(lengths[fieldIdx])
				let raw = UnsafeMutablePointer<UInt8>(row[fieldIdx])
				let s = UTF8Encoding.encode(GenerateFromPointer(from: raw, count: len))
				ret.append(s)
			}
			return ret
		}
		
		public func forEachRow(callback: (Element) -> ()) {
			while true {
				let row = mysql_fetch_row(self.ptr)
				guard row != nil else {
					return
				}
				
				let lengths = mysql_fetch_lengths(self.ptr)
				var ret = [String]()
				
				for fieldIdx in 0..<self.numFields() {
					let len = Int(lengths[fieldIdx])
					let raw = UnsafeMutablePointer<UInt8>(row[fieldIdx])
					let s = UTF8Encoding.encode(GenerateFromPointer(from: raw, count: len))
					ret.append(s)
				}
				callback(ret)
			}
		}
	}
}

public class MySQLStmt {
	var ptr: UnsafeMutablePointer<MYSQL_STMT>
	var paramBinds = UnsafeMutablePointer<MYSQL_BIND>()
	var paramBindsOffset = 0
	
	public enum BindType {
		case Date(String), DateTime(String)
	}
	
	public enum FetchResult {
		case OK, Error, NoData, DataTruncated
	}
	
	public init(_ mysql: MySQL) {
		self.ptr = mysql_stmt_init(mysql.ptr)
	}
	
	deinit {
		self.close()
	}
	
	public func close() {
		clearBinds()
		if self.ptr != nil {
			mysql_stmt_close(self.ptr)
			self.ptr = nil
		}
	}
	
	public func reset() {
		clearBinds()
		mysql_stmt_reset(self.ptr)
	}
	
	func clearBinds() {
		let count = self.paramBindsOffset
		if count > 0 {
			for i in 0..<count {
				switch self.paramBinds[i].buffer_type.rawValue {
				case MYSQL_TYPE_DOUBLE.rawValue:
					UnsafeMutablePointer<Double>(self.paramBinds[i].buffer).dealloc(1)
				case MYSQL_TYPE_LONGLONG.rawValue:
					UnsafeMutablePointer<Int64>(self.paramBinds[i].buffer).dealloc(1)
				case MYSQL_TYPE_VAR_STRING.rawValue,
					MYSQL_TYPE_DATE.rawValue,
					MYSQL_TYPE_DATETIME.rawValue:
					UnsafeMutablePointer<Int8>(self.paramBinds[i].buffer).dealloc(Int(self.paramBinds[i].buffer_length))
				case MYSQL_TYPE_LONG_BLOB.rawValue:
					()
				default:
					assertionFailure("Unhandled MySQL type \(self.paramBinds[i].buffer_type)")
				}
				if self.paramBinds[i].length != nil {
					self.paramBinds[i].length.dealloc(1)
				}
			}
			self.paramBinds.destroy(count)
			self.paramBinds.dealloc(count)
			self.paramBindsOffset = 0
		}
	}
	
	public func freeResult() {
		mysql_stmt_free_result(self.ptr)
	}
	
	public func errorCode() -> UInt32 {
		return mysql_stmt_errno(self.ptr)
	}
	
	public func errorMessage() -> String {
		return String.fromCString(mysql_stmt_error(self.ptr)) ?? ""
	}
	
	public func prepare(query: String) -> Bool {
		let utf8Chars = query.utf8
		let r = mysql_stmt_prepare(self.ptr, query, UInt(utf8Chars.count))
		guard r == 0 else {
			return false
		}
		let count = self.paramCount()
		if count > 0 {
			self.paramBinds = UnsafeMutablePointer<MYSQL_BIND>.alloc(count)
			let initBind = MYSQL_BIND()
			for i in 0..<count {
				self.paramBinds.advancedBy(i).initialize(initBind)
			}
			
		}
		return true
	}
	
	public func execute() -> Bool {
		if self.paramBindsOffset > 0 {
			guard 0 == mysql_stmt_bind_param(self.ptr, self.paramBinds) else {
				return false
			}
		}
		let r = mysql_stmt_execute(self.ptr)
		return r == 0
	}
	
	public func fetch() -> FetchResult {
		let r = mysql_stmt_fetch(self.ptr)
		switch r {
		case 0:
			return .OK
		case 1:
			return .Error
		case MYSQL_NO_DATA:
			return .NoData
		case MYSQL_DATA_TRUNCATED:
			return .DataTruncated
		default:
			return .Error
		}
	}
	
	public func numRows() -> UInt {
		return UInt(mysql_stmt_num_rows(self.ptr))
	}
	
	public func affectedRows() -> UInt {
		return UInt(mysql_stmt_affected_rows(self.ptr))
	}
	
	public func insertId() -> UInt {
		return UInt(mysql_stmt_insert_id(self.ptr))
	}
	
	public func fieldCount() -> UInt {
		return UInt(mysql_stmt_field_count(self.ptr))
	}
	
	public func nextResult() -> Int {
		let r = mysql_stmt_next_result(self.ptr)
		return Int(r)
	}
	
	public func dataSeek(offset: Int) {
		mysql_stmt_data_seek(self.ptr, my_ulonglong(offset))
	}
	
	public func paramCount() -> Int {
		let r = mysql_stmt_param_count(self.ptr)
		return Int(r)
	}
	
	func bindParam(s: String, type: enum_field_types) -> Bool {
		let convertedTup = MySQL.convertString(s)
		self.paramBinds[self.paramBindsOffset].buffer_type = type
		self.paramBinds[self.paramBindsOffset].buffer_length = UInt(convertedTup.1-1)
		self.paramBinds[self.paramBindsOffset].length = UnsafeMutablePointer<UInt>.alloc(1)
		self.paramBinds[self.paramBindsOffset].length.initialize(UInt(convertedTup.1-1))
		self.paramBinds[self.paramBindsOffset].buffer = UnsafeMutablePointer<()>(convertedTup.0)
		
		self.paramBindsOffset += 1
		return true
	}
	
	public func bindParam(type: BindType) -> Bool {
		switch type {
		case .Date(let s):
			self.bindParam(s, type: MYSQL_TYPE_DATE)
		case .DateTime(let s):
			self.bindParam(s, type: MYSQL_TYPE_DATETIME)
		}
		return true
	}
	
	public func bindParam(d: Double) -> Bool {
		self.paramBinds[self.paramBindsOffset].buffer_type = MYSQL_TYPE_DOUBLE
		self.paramBinds[self.paramBindsOffset].buffer_length = UInt(sizeof(Double))
		let a = UnsafeMutablePointer<Double>.alloc(1)
		a.initialize(d)
		self.paramBinds[self.paramBindsOffset].buffer = UnsafeMutablePointer<()>(a)
		
		self.paramBindsOffset += 1
		return true
	}
	
	public func bindParam(i: Int) -> Bool {
		self.paramBinds[self.paramBindsOffset].buffer_type = MYSQL_TYPE_LONGLONG
		self.paramBinds[self.paramBindsOffset].buffer_length = UInt(sizeof(Int64))
		let a = UnsafeMutablePointer<Int64>.alloc(1)
		a.initialize(Int64(i))
		self.paramBinds[self.paramBindsOffset].buffer = UnsafeMutablePointer<()>(a)
		
		self.paramBindsOffset += 1
		return true
	}
	
	public func bindParam(s: String) -> Bool {
		let convertedTup = MySQL.convertString(s)
		self.paramBinds[self.paramBindsOffset].buffer_type = MYSQL_TYPE_VAR_STRING
		self.paramBinds[self.paramBindsOffset].buffer_length = UInt(convertedTup.1-1)
		self.paramBinds[self.paramBindsOffset].length = UnsafeMutablePointer<UInt>.alloc(1)
		self.paramBinds[self.paramBindsOffset].length.initialize(UInt(convertedTup.1-1))
		self.paramBinds[self.paramBindsOffset].buffer = UnsafeMutablePointer<()>(convertedTup.0)
		
		self.paramBindsOffset += 1
		return true
	}
	
	public func bindParam(b: UnsafePointer<Int8>, length: Int) -> Bool {
		self.paramBinds[self.paramBindsOffset].buffer_type = MYSQL_TYPE_LONG_BLOB
		self.paramBinds[self.paramBindsOffset].buffer_length = UInt(length)
		self.paramBinds[self.paramBindsOffset].length = UnsafeMutablePointer<UInt>.alloc(1)
		self.paramBinds[self.paramBindsOffset].length.initialize(UInt(length))
		self.paramBinds[self.paramBindsOffset].buffer = UnsafeMutablePointer<()>(b)
		
		self.paramBindsOffset += 1
		return true
	}
	
	// null
	public func bindParam() -> Bool {
		self.paramBinds[self.paramBindsOffset].buffer_type = MYSQL_TYPE_NULL
		self.paramBinds[self.paramBindsOffset].length = UnsafeMutablePointer<UInt>.alloc(1)
		self.paramBindsOffset += 1
		return true
	}
	
	public class Results: GeneratorType {
		let stmt: MySQLStmt
		public typealias Element = [Any?]
		
		init(_ stmt: MySQLStmt) {
			self.stmt = stmt
		}
		
		deinit {
			self.close()
		}
		
		public func close() {
			
		}
		
		public func numRows() -> Int {
			return Int(self.stmt.numRows())
		}
		
		public func numFields() -> Int {
			return Int(self.stmt.fieldCount())
		}
		
		public func next() -> Element? {
			
			return nil
		}
		
		public func forEachRow(callback: (Element) -> ()) {
			let numFields = self.numFields()
			let binds = UnsafeMutablePointer<MYSQL_BIND>.alloc(numFields)
			let blankBind = MYSQL_BIND()
			for i in 0..<numFields {
				binds.advancedBy(i).initialize(blankBind)
			}
			
		}
	}
}


























