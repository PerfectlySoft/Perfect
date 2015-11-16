//
//  PGPerfectObject.swift
//  PostgreSQL
//
//  Created by Kyle Jessup on 2015-08-04.
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


import Foundation
import PerfectLib

public class PGPerfectObject : PerfectObject {

}

public class PGPerfectObjectDriver: PerfectObjectDriver {
	
	var _p: PGConnection
	
	var p: PGConnection {
		set {
			self._p = newValue
		}
		get {
			return self._p // !FIX! ping
		}
	}
	
	public init(conn: PGConnection) {
		self._p = conn
	}
	
	public func conn() -> PGConnection {
		return self.p
	}
	
	public func close() {
		self.p.close()
	}
	
	private func exec(statement: String, params: [String]) -> PGResult {
		let r = self.p.exec(statement, params: params)
		return r
	}
	
	private func exec(statement: String) -> PGResult {
		let r = self.p.exec(statement)
		return r
	}
	
	public func delete(type: PerfectObject) -> (Int, String) {
		let r = exec("DELETE FROM \(type.tableName()) WHERE \(type.primaryKeyName()) = $1::uuid", params: [String.fromUUID(type.objectId())])
		guard r.status() == .CommandOK else {
			return (r.statusInt(), r.errorMessage())
		}
		return (0, "")
	}
	
	public func load<T : PerfectObject>(type: T, withId: uuid_t) -> T {
		let r = exec("SELECT * FROM \(type.tableName()) WHERE \(type.primaryKeyName()) = $1::uuid", params: [String.fromUUID(withId)])
		if r.status() == .TuplesOK && r.numTuples() == 1 {
			var dict = [String:String]()
			let numFields = r.numFields()
			for idx in 0..<numFields {
				dict[r.fieldName(idx)!] = r.getFieldString(0, fieldIndex: idx)
			}
			type.load(dict)
		}
		return type
	}
	
	public func load<T : PerfectObject>(type: T, withUniqueField: (String,String)) -> T {
		let r = exec("SELECT * FROM \(type.tableName()) WHERE \(withUniqueField.0) = $1", params: [withUniqueField.1])
		defer { r.close() }
		if r.status() == .TuplesOK && r.numTuples() > 0 {
			var dict = [String:String]()
			let numFields = r.numFields()
			for idx in 0..<numFields {
				dict[r.fieldName(idx)!] = r.getFieldString(0, fieldIndex: idx)
			}
			type.load(dict)
		}
		return type
	}
	
	func commitOneChange(type: PerfectObject) -> (Int, String) {
		let dict = type.unloadDirty()
		guard dict.count > 0 else {
			return (0, "")
		}
		var values = [String]()
		var statement = "UPDATE \(type.tableName()) SET "
		var i = 0
		for (key, value) in dict where key != type.primaryKeyName() {
			if i != 0 {
				statement.appendContentsOf(",")
			}
			++i
			statement.appendContentsOf("\(key)=$\(i)")
			values.append(value)
		}
		statement.appendContentsOf(" WHERE \(type.primaryKeyName())=$\(++i)::uuid")
		values.append(String.fromUUID(type.objectId()))
		let r = exec(statement, params: values)
		guard r.status() == .CommandOK else {
			return (r.statusInt(), r.errorMessage())
		}
		return (0, "")
	}
	
	public func commitChanges(type: PerfectObject) -> (Int, String) {
		exec("BEGIN")
		let ret = self.commitOneChange(type)
		exec("COMMIT")
		return ret
	}
	
	public func commitChanges(types: [PerfectObject]) -> [(Int, String)] {
		exec("BEGIN")
		let ret = types.map { self.commitOneChange($0) }
		exec("COMMIT")
		return ret
	}
	
	private func makeOrderByClause(o: PerfectObject) -> String {
		if let orderBy = o.orderBy() {
			return " ORDER BY \"" + orderBy + "\"" + (o.orderDesc() ? " DESC" : "")
		}
		return ""
	}
	
	public func joinTable<T : PerfectObject>(type: PerfectObject, name: String) -> [T] {
		
		let typeTableName = type.tableName()
		var keyField = "id_"
		if typeTableName.hasSuffix("s") {
			keyField.appendContentsOf(typeTableName.substringToIndex(typeTableName.endIndex.predecessor()))
		} else {
			keyField.appendContentsOf(typeTableName)
		}
		
		let statement = "SELECT * FROM \(name) WHERE \(keyField) = $1::uuid" + self.makeOrderByClause(T(driver: self))
		let r = exec(statement, params: [String.fromUUID(type.objectId())])
		defer { r.close() }
		let numFields = r.numFields()
		let numTuples = r.numTuples()
		guard numTuples > 0 else {
			return [T]()
		}
		var results = [T]()
		for tupleIdx in 0..<numTuples {
			var dict = [String:String]()
			for fieldIdx in 0..<numFields {
				dict[r.fieldName(fieldIdx)!] = r.getFieldString(tupleIdx, fieldIndex: fieldIdx)
			}
			let t = T(driver: self)
			t.load(dict)
			results.append(t)
		}
		return results
	}
	
	// Some of the initial values may not match the db fields
	// For example, a user may be created with a password but the password is in another table
	// Only use fields which exist for this object's table, but pass in all the fields
	// to the created() method
	public func create<T : PerfectObject>(withFields: [(String,String)]) -> T {
		let type = T(driver: self)
		
		var fieldsSet = Set<String>()
		for fn in type.fieldList() {
			fieldsSet.insert(fn)
		}
		
		var uuid = ""
		
		// explicit primary key
		for (key, value) in withFields where fieldsSet.contains(key) && key == type.primaryKeyName() {
			uuid = value
		}
		
		if uuid.isEmpty {
			uuid = String.fromUUID(generateUUID())
		}
		
		var values = [String]()
		var statement = "INSERT INTO \(type.tableName()) (\(type.primaryKeyName())"
		for (key, _) in withFields where fieldsSet.contains(key) && key != type.primaryKeyName() {
			statement.appendContentsOf(",\(key)")
		}
		statement.appendContentsOf(") VALUES ($1::uuid")
		var i = 2
		values.append(uuid)
		for (key, value) in withFields where fieldsSet.contains(key) && key != type.primaryKeyName() {
			statement.appendContentsOf(",$\(i++)")
			values.append(value)
		}
		statement.appendContentsOf(")")
		let r0 = exec(statement, params: values)
		if r0.status() == .CommandOK {
			self.load(type, withId: uuid.asUUID())
			type.created(withFields)
		} else {
			print("PGPerfectObjectDriver error: " + r0.errorMessage())
		}
		return type
	}
	
	public func list<T : PerfectObject>() -> [T] {
		var ret = [T]()
		let type = T(driver: self)
		let fieldList = type.fieldList()
		let fields = fieldList.map { "\""+$0+"\"" } .joinWithSeparator(",")
		let statement = "SELECT \( fields ) FROM \(type.tableName())" + self.makeOrderByClause(type)
		let r = exec(statement)
		if r.status() == .TuplesOK && r.numTuples() > 0 {
			let numFields = r.numFields()
			let numTuples = r.numTuples()
			for tupleIdx in 0..<numTuples {
				var dict = [String:String]()
				for fieldIdx in 0..<numFields {
					dict[r.fieldName(fieldIdx)!] = r.getFieldString(tupleIdx, fieldIndex: fieldIdx)
				}
				let t = T(driver: self)
				t.load(dict)
				ret.append(t)
			}
		}
		return ret
	}
	
	public func list<T : PerfectObject>(withCriterion: (String,String)) -> [T] {
		var ret = [T]()
		let type = T(driver: self)
		let fieldList = type.fieldList()
		let fields = fieldList.map { "\""+$0+"\"" } .joinWithSeparator(",")
		let statement = "SELECT \( fields ) FROM \(type.tableName()) WHERE \(withCriterion.0) = $1" + self.makeOrderByClause(type)
		let params = [withCriterion.1]
		let r = exec(statement, params: params)
		if r.status() == .TuplesOK && r.numTuples() > 0 {
			let numFields = r.numFields()
			let numTuples = r.numTuples()
			for tupleIdx in 0..<numTuples {
				var dict = [String:String]()
				for fieldIdx in 0..<numFields {
					dict[r.fieldName(fieldIdx)!] = r.getFieldString(tupleIdx, fieldIndex: fieldIdx)
				}
				let t = T(driver: self)
				t.load(dict)
				ret.append(t)
			}
		}
		return ret
	}
	
}






