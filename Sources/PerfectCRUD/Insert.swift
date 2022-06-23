//
//  PerfectCRUDInsert.swift
//  PerfectCRUD
//
//  Created by Kyle Jessup on 2017-12-02.
//

import Foundation

public struct Insert<OAF: Codable, A: TableProtocol>: FromTableProtocol, CommandProtocol {
	public typealias FromTableType = A
	public typealias OverAllForm = OAF
	public let fromTable: FromTableType
	public let sqlGenState: SQLGenState
	init(fromTable ft: FromTableType, instances: [OAF], includeKeys: [PartialKeyPath<OAF>], excludeKeys: [PartialKeyPath<OAF>]) throws {
		fromTable = ft
		let delegate = ft.databaseConfiguration.sqlGenDelegate
		var state = SQLGenState(delegate: delegate)
		state.command = .insert
		try ft.setState(state: &state)
		let td = state.tableData[0]
		let kpDecoder = td.keyPathDecoder
		guard let kpInstance = td.modelInstance else {
			throw CRUDSQLGenError("Could not get model instance for key path decoder \(OAF.self)")
		}
		let includeNames: [String]
		if includeKeys.isEmpty {
			let columnDecoder = CRUDColumnNameDecoder()
			_ = try OverAllForm.init(from: columnDecoder)
			includeNames = columnDecoder.collectedKeys.map { $0.name }
		} else {
			includeNames = try includeKeys.map {
				guard let n = try kpDecoder.getKeyPathName(kpInstance, keyPath: $0) else {
					throw CRUDSQLGenError("Could not get key path name for \(OAF.self) \($0)")
				}
				return n
			}
		}
		let excludeNames: [String] = try excludeKeys.map {
			guard let n = try kpDecoder.getKeyPathName(kpInstance, keyPath: $0) else {
				throw CRUDSQLGenError("Could not get key path name for \(OAF.self) \($0)")
			}
			return n
		}

		let encoder = try CRUDBindingsEncoder(delegate: delegate)
		try instances[0].encode(to: encoder)

		let bindings = try encoder.completedBindings(allKeys: includeNames, ignoreKeys: Set(excludeNames))
		let columnNames = try bindings.map { try delegate.quote(identifier: $0.column) }
		let bindIdentifiers = bindings.map { $0.identifier }

		let nameQ = try delegate.quote(identifier: "\(OAF.CRUDTableName)")
		let sqlStr: String
		if columnNames.isEmpty {
			sqlStr = "INSERT INTO \(nameQ) \(delegate.getEmptyInsertSnippet())"
		} else {
			sqlStr = "INSERT INTO \(nameQ) (\(columnNames.joined(separator: ", "))) VALUES (\(bindIdentifiers.joined(separator: ", ")))"
		}
		CRUDLogging.log(.query, sqlStr)
		sqlGenState = state
		let exeDelegate = try databaseConfiguration.sqlExeDelegate(forSQL: sqlStr)
		try exeDelegate.bind(delegate.bindings)
		_ = try exeDelegate.hasNext()

		for instance in instances[1...] {
			let delegate = databaseConfiguration.sqlGenDelegate
			let encoder = try CRUDBindingsEncoder(delegate: delegate)
			try instance.encode(to: encoder)
			_ = try encoder.completedBindings(allKeys: includeNames, ignoreKeys: Set(excludeNames))
			try exeDelegate.bind(delegate.bindings)
			_ = try exeDelegate.hasNext()
		}
	}
}

public extension Table {
	@discardableResult
	func insert(_ instances: [Form]) throws -> Insert<Form, Table> {
		return try .init(fromTable: self, instances: instances, includeKeys: [], excludeKeys: [])
	}
	@discardableResult
	func insert(_ instance: Form) throws -> Insert<Form, Table> {
		return try .init(fromTable: self, instances: [instance], includeKeys: [], excludeKeys: [])
	}
	@discardableResult
	func insert<Z: Decodable>(_ instances: [Form], setKeys: KeyPath<OverAllForm, Z>, _ rest: PartialKeyPath<OverAllForm>...) throws -> Insert<Form, Table> {
		return try .init(fromTable: self, instances: instances, includeKeys: [setKeys] + rest, excludeKeys: [])
	}
	@discardableResult
	func insert<Z: Decodable>(_ instance: Form, setKeys: KeyPath<OverAllForm, Z>, _ rest: PartialKeyPath<OverAllForm>...) throws -> Insert<Form, Table> {
		return try .init(fromTable: self, instances: [instance], includeKeys: [setKeys] + rest, excludeKeys: [])
	}
	@discardableResult
	func insert<Z: Decodable>(_ instances: [Form], ignoreKeys: KeyPath<OverAllForm, Z>, _ rest: PartialKeyPath<OverAllForm>...) throws -> Insert<Form, Table> {
		return try .init(fromTable: self, instances: instances, includeKeys: [], excludeKeys: [ignoreKeys] + rest)
	}
	@discardableResult
	func insert<Z: Decodable>(_ instance: Form, ignoreKeys: KeyPath<OverAllForm, Z>, _ rest: PartialKeyPath<OverAllForm>...) throws -> Insert<Form, Table> {
		return try .init(fromTable: self, instances: [instance], includeKeys: [], excludeKeys: [ignoreKeys] + rest)
	}
}
