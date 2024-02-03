//
//  PerfectCRUDDelete.swift
//  PerfectCRUD
//
//  Created by Kyle Jessup on 2017-12-03.
//

import Foundation

public protocol Deleteable: TableProtocol {
	@discardableResult
	func delete() throws -> Delete<OverAllForm, Self>
}

public extension Deleteable {
	@discardableResult
	func delete() throws -> Delete<OverAllForm, Self> {
		return try .init(fromTable: self)
	}
}

public struct Delete<OAF: Codable, A: TableProtocol>: FromTableProtocol, CommandProtocol {
	public typealias FromTableType = A
	public typealias OverAllForm = OAF
	public let fromTable: FromTableType
	public let sqlGenState: SQLGenState
	init(fromTable ft: FromTableType) throws {
		fromTable = ft
		let delegate = ft.databaseConfiguration.sqlGenDelegate
		var state = SQLGenState(delegate: delegate)
		state.command = .delete
		try ft.setState(state: &state)
		try ft.setSQL(state: &state)
		sqlGenState = state
		for stat in state.statements {
			let exeDelegate = try databaseConfiguration.sqlExeDelegate(forSQL: stat.sql)
			try exeDelegate.bind(stat.bindings)
			_ = try exeDelegate.hasNext()
		}
	}
}
