//
//  PerfectObject.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2015-08-04.
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


import Foundation

public enum HandlerAction {
	case None
	case Load
	case Create
	case Delete
	case Commit
	case List
}

extension HandlerAction {
	public func asString() -> String {
		switch self {
		case .None:
			return "none"
		case .Load:
			return "load"
		case .Create:
			return "create"
		case .Delete:
			return "delete"
		case .Commit:
			return "commit"
		case .List:
			return "list"
		}
	}
	
	public static func fromString(s:String) -> HandlerAction {
		switch s {
		case HandlerAction.Load.asString():
			return .Load
		case HandlerAction.Create.asString():
			return .Create
		case HandlerAction.Delete.asString():
			return .Delete
		case HandlerAction.Commit.asString():
			return .Commit
		case HandlerAction.List.asString():
			return .List
		default:
			return .None
		}
	}
}

public protocol PerfectObjectDriver : Closeable {
	func load<T : PerfectObject>(type: T, withId: uuid_t) -> T
	func load<T : PerfectObject>(type: T, withUniqueField: (String,String)) -> T
	func delete(type: PerfectObject) -> (Int, String)
	func commitChanges(type: PerfectObject) -> (Int, String)
	func commitChanges(types: [PerfectObject]) -> [(Int, String)]
	func create<T : PerfectObject>(withFields: [(String,String)]) -> T
	func joinTable<T : PerfectObject>(type: PerfectObject, name: String) -> [T]
	func list<T : PerfectObject>() -> [T]
	func list<T : PerfectObject>(withCriterion: (String,String)) -> [T]
}

extension PerfectObjectDriver {
	public func generateUUID() -> uuid_t {		
		return random_uuid()
	}
}

public class PerfectObject {
	
	// Caching on joined tables
	var joinCache = [String:[PerfectObject]]()
	
	let driver: PerfectObjectDriver
	var id: uuid_t = empty_uuid()
	var pkName = "id"
	var simpleNameStr = ""
	var _orderBy: String?
	var _orderDesc: Bool = false
	
	/// The driver must be passed down to any newly loaded objects.
	/// It is assumed that the children of a PerfectObject will have the same driver *instance* as the parent.
	public required init(driver: PerfectObjectDriver) {
		self.driver = driver
	}
	
	/// Objects will have valid ids if they have been successfully loaded or created
	public func hasValidID() -> Bool {
		let empty = empty_uuid()
		let id = self.id
		if id.0 != empty.0 { return true }
		if id.1 != empty.1 { return true }
		if id.2 != empty.2 { return true }
		if id.3 != empty.3 { return true }
		if id.4 != empty.4 { return true }
		if id.5 != empty.5 { return true }
		if id.6 != empty.6 { return true }
		if id.7 != empty.7 { return true }
		if id.8 != empty.8 { return true }
		if id.9 != empty.9 { return true }
		if id.10 != empty.10 { return true }
		if id.11 != empty.11 { return true }
		if id.12 != empty.12 { return true }
		if id.13 != empty.13 { return true }
		if id.14 != empty.14 { return true }
		if id.15 != empty.15 { return true }
		return false
	}
	
	/// Provides access to the object driver for this instance
	public func objectDriver() -> PerfectObjectDriver {
		return self.driver
	}
	
	/// Sets the name of hte primary key
	/// Should be called by sub-classes only
	public func setPrimaryKeyName(to: String) {
		self.pkName = to
	}
	
	/// Provides access to the object's primary key field name
	public func primaryKeyName() -> String {
		return self.pkName
	}
	
	public func setOrderBy(to: String) {
		self._orderBy = to
	}
	
	public func orderBy() -> String? {
		return self._orderBy
	}
	
	public func setOrderDesc(to: Bool) {
		self._orderDesc = to
	}
	
	public func orderDesc() -> Bool {
		return self._orderDesc
	}
	
	public func setSimpleName(to: String) {
		self.simpleNameStr = to
	}
	
	public func simpleName() -> String {
		return self.simpleNameStr
	}
	
	/// The unique id for this object, within its table.
	public func objectId() -> uuid_t {
		return self.id
	}
	
	public func setObjectId(id: uuid_t) {
		self.id = id
	}
	
	/// Read the values from a table to populate the object.
	/// Sub-classes will override this method to load their own custom properties.
	public func load(dict: [String:String], markClean: Bool = true) {
		if let findId = dict[primaryKeyName()] {
			let uuid = findId.asUUID()
			self.id = uuid
		}
	}
	
	/// Returns only the properties of the type which have been modified since loading
	public func unloadDirty() -> [String:String] {
		return [String:String]()
	}
	
	/// Returns the values from this object which would be written to the table.
	/// Sub-classes will overrride this to introduce their own custom properties
	public func unload() -> [String:String] {
		return [primaryKeyName():String.fromUUID(self.id)]
	}
	
	public func fieldList() -> [String] {
		return [primaryKeyName()]
	}
	
	public func tableName() -> String {
		return "Not overridden"
	}
	
	public func joinTable<T : PerfectObject>(name: String) -> [T] {
		if let found = self.joinCache[name] as! [T]? {
			return found
		}
		let fnd: [T] = self.driver.joinTable(self, name: name)
		if fnd.count > 0 {
			self.joinCache[name] = fnd
		}
		return fnd
	}
	
	public func clearJoins(named: String) {
		self.joinCache.removeValueForKey(named)
	}
	
	public func created(withFields: [(String,String)]) {
		
	}
}




