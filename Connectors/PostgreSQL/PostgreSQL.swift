//
//  PostgreSQL.swift
//  PostgreSQL
//
//  Created by Kyle Jessup on 2015-07-29.
//	Copyright (C) 2015 PerfectlySoft, Inc.
//
//	This program is free software: you can redistribute it and/or modify
//	it under the terms of the GNU Affero General Public License as
//	published by the Free Software Foundation, either version 3 of the
//	License, or (at your option) any later version, as supplemented by the
//	Perfect Additional Terms.
//
//	This program is distributed in the hope that it will be useful,
//	but WITHOUT ANY WARRANTY; without even the implied warranty of
//	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//	GNU Affero General Public License, as supplemented by the
//	Perfect Additional Terms, for more details.
//
//	You should have received a copy of the GNU Affero General Public License
//	and the Perfect Additional Terms that immediately follow the terms and
//	conditions of the GNU Affero General Public License along with this
//	program. If not, see <http://www.perfect.org/AGPL_3_0_With_Perfect_Additional_Terms.txt>.
//


import libpq

public final class PGResult {
	
	public enum StatusType {
		case EmptyQuery
		case CommandOK
		case TuplesOK
		case BadResponse
		case NonFatalError
		case FatalError
		case SingleTuple
		case Unknown
	}
	
	var res: COpaquePointer
	
	init(_ res: COpaquePointer) {
		self.res = res
	}
	
	deinit {
		close()
	}
	
	public func close() {
		clear()
	}
	
	public func clear() {
		if res != nil {
			PQclear(res)
			res = COpaquePointer()
		}
	}
	
	public func statusInt() -> Int {
		let s = PQresultStatus(res)
		return Int(s.rawValue)
	}
	
	public func status() -> StatusType {
		let s = PQresultStatus(res)
		switch(s.rawValue) {
		case PGRES_EMPTY_QUERY.rawValue:
			return .EmptyQuery
		case PGRES_COMMAND_OK.rawValue:
			return .CommandOK
		case PGRES_TUPLES_OK.rawValue:
			return .TuplesOK
		case PGRES_BAD_RESPONSE.rawValue:
			return .BadResponse
		case PGRES_NONFATAL_ERROR.rawValue:
			return .NonFatalError
		case PGRES_FATAL_ERROR.rawValue:
			return .FatalError
		case PGRES_SINGLE_TUPLE.rawValue:
			return .SingleTuple
		default:
			print("Unhandled PQresult status type \(s.rawValue)")
		}
		return .Unknown
	}
	
	public func errorMessage() -> String {
		return String.fromCString(PQresultErrorMessage(res)) ?? ""
	}
	
	public func numFields() -> Int {
		return Int(PQnfields(res))
	}
	
	public func fieldName(index: Int) -> String? {
		let fn = PQfname(res, Int32(index))
		if fn != nil {
			return String.fromCString(fn) ?? ""
		}
		return nil
	}
	
	public func fieldType(index: Int) -> Oid? {
		let fn = PQftype(res, Int32(index))
		return fn
	}
	
	public func numTuples() -> Int {
		return Int(PQntuples(res))
	}
	
	public func fieldIsNull(tupleIndex: Int, fieldIndex: Int) -> Bool {
		return 1 == PQgetisnull(res, Int32(tupleIndex), Int32(fieldIndex))
	}
	
	public func getFieldString(tupleIndex: Int, fieldIndex: Int) -> String {
		let v = PQgetvalue(res, Int32(tupleIndex), Int32(fieldIndex))
		return String.fromCString(v) ?? ""
	}
	
	public func getFieldInt(tupleIndex: Int, fieldIndex: Int) -> Int {
		let s = getFieldString(tupleIndex, fieldIndex: fieldIndex)
		return Int(s) ?? 0
	}
	
	public func getFieldBool(tupleIndex: Int, fieldIndex: Int) -> Bool {
		let s = getFieldString(tupleIndex, fieldIndex: fieldIndex)
		return s == "t"
	}
	
	public func getFieldInt8(tupleIndex: Int, fieldIndex: Int) -> Int8 {
		let s = getFieldString(tupleIndex, fieldIndex: fieldIndex)
		return Int8(s) ?? 0
	}
	
	public func getFieldInt16(tupleIndex: Int, fieldIndex: Int) -> Int16 {
		let s = getFieldString(tupleIndex, fieldIndex: fieldIndex)
		return Int16(s) ?? 0
	}
	
	public func getFieldInt32(tupleIndex: Int, fieldIndex: Int) -> Int32 {
		let s = getFieldString(tupleIndex, fieldIndex: fieldIndex)
		return Int32(s) ?? 0
	}
	
	public func getFieldInt64(tupleIndex: Int, fieldIndex: Int) -> Int64 {
		let s = getFieldString(tupleIndex, fieldIndex: fieldIndex)
		return Int64(s) ?? 0
	}
	
	public func getFieldDouble(tupleIndex: Int, fieldIndex: Int) -> Double {
		let s = getFieldString(tupleIndex, fieldIndex: fieldIndex)
		return Double(s) ?? 0
	}
	
	public func getFieldFloat(tupleIndex: Int, fieldIndex: Int) -> Float {
		let s = getFieldString(tupleIndex, fieldIndex: fieldIndex)
		return Float(s) ?? 0
	}
	
	public func getFieldBlob(tupleIndex: Int, fieldIndex: Int) -> [Int8] {
		let v = PQgetvalue(res, Int32(tupleIndex), Int32(fieldIndex))
		let length = Int(PQgetlength(res, Int32(tupleIndex), Int32(fieldIndex)))
		let ip = UnsafePointer<Int8>(v)
		var ret = [Int8]()
		for idx in 0..<length {
			ret.append(ip[idx])
		}
		return ret
	}
}

public final class PGConnection {
	
	public enum StatusType {
		case OK
		case Bad
	}
	
	var conn = COpaquePointer()
	var connectInfo: String = ""
	
	public init() {
		
	}
	
	deinit {
		close()
	}
	
	public func connectdb(info: String) -> StatusType {
		conn = PQconnectdb(info)
		connectInfo = info
		return status()
	}
	
	public func close() {
		finish()
	}
	
	public func finish() {
		if conn != nil {
			PQfinish(conn)
			conn = COpaquePointer()
		}
	}
	
	public func status() -> StatusType {
		let status = PQstatus(conn)
		return status == CONNECTION_OK ? .OK : .Bad
	}
	
	public func errorMessage() -> String {
		return String.fromCString(PQerrorMessage(conn)) ?? ""
	}
	
	public func exec(statement: String) -> PGResult {
		return PGResult(PQexec(conn, statement))
	}
	
	// !FIX! does not handle binary data
	public func exec(statement: String, params: [String]) -> PGResult {
		var asStrings = [String]()
		for item in params {
			asStrings.append(String(item))
		}
		let count = asStrings.count
		let values = UnsafeMutablePointer<UnsafePointer<Int8>>.alloc(count)
		
		defer {
			values.destroy() ; values.dealloc(count)
		}
		var temps = [Array<UInt8>]()
		for idx in 0..<count {
			let s = asStrings[idx]
			let utf8 = s.utf8
			var aa = Array<UInt8>(utf8)
			aa.append(0)
			temps.append(aa)
			values[idx] = UnsafePointer<Int8>(temps.last!)
		}
		
		let r = PQexecParams(conn, statement, Int32(count), nil, values, nil, nil, Int32(0))
		return PGResult(r)
	}
}







