//
//  PerfectCRUDWhere.swift
//  PerfectCRUD
//
//  Created by Kyle Jessup on 2018-01-03.
//

import Foundation

public struct Where<OAF: Codable, A: TableProtocol>: TableProtocol, FromTableProtocol, Selectable {
	public typealias Form = OAF
	public typealias FromTableType = A
	public typealias OverAllForm = OAF
	public let fromTable: FromTableType
	let expression: Expression
	public func setState(state: inout SQLGenState) throws {
		try fromTable.setState(state: &state)
		state.whereExpr = expression
	}
	public func setSQL(state: inout SQLGenState) throws {
		try fromTable.setSQL(state: &state)
	}
}

public extension Where where OverAllForm == FromTableType.Form {
	@discardableResult
	func delete() throws -> Delete<OverAllForm, Where> {
		return try .init(fromTable: self)
	}
	@discardableResult
	func update(_ instance: OverAllForm) throws -> Update<OverAllForm, Where> {
		return try .init(fromTable: self, instance: instance, includeKeys: [], excludeKeys: [])
	}
	@discardableResult
	func update<Z: Encodable>(_ instance: OverAllForm, setKeys: KeyPath<OverAllForm, Z>, _ rest: PartialKeyPath<OverAllForm>...) throws -> Update<OverAllForm, Where> {
		return try .init(fromTable: self, instance: instance, includeKeys: [setKeys] + rest, excludeKeys: [])
	}
	@discardableResult
	func update<Z: Encodable>(_ instance: OverAllForm, ignoreKeys: KeyPath<OverAllForm, Z>, _ rest: PartialKeyPath<OverAllForm>...) throws -> Update<OverAllForm, Where> {
		return try .init(fromTable: self, instance: instance, includeKeys: [], excludeKeys: [ignoreKeys] + rest)
	}
}
