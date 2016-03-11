//
//  PostgreSQL.swift
//  PostgreSQL
//
//  Created by Kyle Jessup on 2015-07-29.
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
		self.close()
	}
	
	public func close() {
		self.clear()
	}
	
	public func clear() {
		if self.res != nil {
			PQclear(self.res)
			self.res = COpaquePointer()
		}
	}
	
	public func statusInt() -> Int {
		let s = PQresultStatus(self.res)
		return Int(s.rawValue)
	}
	
	public func status() -> StatusType {
		let s = PQresultStatus(self.res)
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
		return String.fromCString(PQresultErrorMessage(self.res)) ?? ""
	}
	
	public func numFields() -> Int {
		return Int(PQnfields(self.res))
	}
	
	public func fieldName(index: Int) -> String? {
		let fn = PQfname(self.res, Int32(index))
		if fn != nil {
			return String.fromCString(fn) ?? ""
		}
		return nil
	}
	
	public func fieldType(index: Int) -> Oid? {
		let fn = PQftype(self.res, Int32(index))
		return fn
	}
	
	public func numTuples() -> Int {
		return Int(PQntuples(self.res))
	}
	
	public func fieldIsNull(tupleIndex: Int, fieldIndex: Int) -> Bool {
		return 1 == PQgetisnull(self.res, Int32(tupleIndex), Int32(fieldIndex))
	}
	
	public func getFieldString(tupleIndex: Int, fieldIndex: Int) -> String {
		let v = PQgetvalue(self.res, Int32(tupleIndex), Int32(fieldIndex))
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
		let v = PQgetvalue(self.res, Int32(tupleIndex), Int32(fieldIndex))
		let length = Int(PQgetlength(self.res, Int32(tupleIndex), Int32(fieldIndex)))
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
		self.close()
	}
	
	public func connectdb(info: String) -> StatusType {
		self.conn = PQconnectdb(info)
		self.connectInfo = info
		return self.status()
	}
	
	public func close() {
		self.finish()
	}
	
	public func finish() {
		if self.conn != nil {
			PQfinish(self.conn)
			self.conn = COpaquePointer()
		}
	}
	
	public func status() -> StatusType {
		let status = PQstatus(self.conn)
		return status == CONNECTION_OK ? .OK : .Bad
	}
	
	public func errorMessage() -> String {
		return String.fromCString(PQerrorMessage(self.conn)) ?? ""
	}
	
	public func exec(statement: String) -> PGResult {
		return PGResult(PQexec(self.conn, statement))
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
		
		let r = PQexecParams(self.conn, statement, Int32(count), nil, values, nil, nil, Int32(0))
		return PGResult(r)
	}
}







