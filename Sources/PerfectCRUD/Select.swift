//
//  PerfectCRUDSelect.swift
//  PerfectCRUD
//
//  Created by Kyle Jessup on 2017-12-02.
//

import Foundation

public struct SelectIterator<A: SelectProtocol>: IteratorProtocol {
	public typealias Element = A.OverAllForm
	let select: A?
	let exeDelegate: SQLExeDelegate?
	init(select s: A) throws {
		select = s
		exeDelegate = try SQLTopExeDelegate(genState: s.sqlGenState, configurator: s.fromTable.databaseConfiguration)
	}
	init() {
		select = nil
		exeDelegate = nil
	}
	public mutating func next() -> Element? {
		guard let delegate = exeDelegate else {
			return nil
		}
		do {
			if try delegate.hasNext() {
				let rowDecoder: CRUDRowDecoder<ColumnKey> = CRUDRowDecoder(delegate: delegate)
				return try Element(from: rowDecoder)
			}
		} catch {
			CRUDLogging.log(.error, "Error thrown in SelectIterator.next(). Caught: \(error)")
		}
		return nil
	}
	public mutating func nextElement() throws -> Element? {
		guard let delegate = exeDelegate else {
			return nil
		}
		if try delegate.hasNext() {
			let rowDecoder: CRUDRowDecoder<ColumnKey> = CRUDRowDecoder(delegate: delegate)
			return try Element(from: rowDecoder)
		}
		return nil
	}
}

public struct Select<OAF: Codable, A: TableProtocol>: SelectProtocol {
	public typealias Iterator = SelectIterator<Select>
	public typealias FromTableType = A
	public typealias OverAllForm = OAF
	public let fromTable: FromTableType
	public let sqlGenState: SQLGenState
	init(fromTable ft: FromTableType) throws {
		fromTable = ft
		var state = SQLGenState(delegate: ft.databaseConfiguration.sqlGenDelegate)
		state.command = .select
		try ft.setState(state: &state)
		try ft.setSQL(state: &state)
		guard state.accumulatedOrderings.isEmpty else {
			throw CRUDSQLGenError("Orderings were not consumed: \(state.accumulatedOrderings)")
		}
		sqlGenState = state
	}
	public func makeIterator() -> Iterator {
		do {
			return try SelectIterator(select: self)
		} catch {
			CRUDLogging.log(.error, "Error thrown in Select.makeIterator() Caught: \(error)")
		}
		return SelectIterator()
	}
}

public struct Ordering<OAF: Codable, A: TableProtocol>: TableProtocol, FromTableProtocol, Joinable, Selectable, Whereable, Orderable, Limitable {
	public typealias Form = A.Form
	public typealias FromTableType = A
	public typealias OverAllForm = OAF
	public let fromTable: FromTableType
	let keys: [PartialKeyPath<A.Form>]
	let descending: Bool
	public func setState(state: inout SQLGenState) throws {
		try fromTable.setState(state: &state)
	}
	public func setSQL(state: inout SQLGenState) throws {
		state.accumulatedOrderings.append(contentsOf: keys.map { (key: $0, desc: descending) })
		try fromTable.setSQL(state: &state)
	}
}

public struct Limit<OAF: Codable, A: TableProtocol>: TableProtocol, FromTableProtocol, Joinable, Selectable, Whereable, Orderable {
	public typealias Form = A.Form
	public typealias FromTableType = A
	public typealias OverAllForm = OAF
	public let fromTable: FromTableType
	let max: Int
	let skip: Int
	public func setState(state: inout SQLGenState) throws {
		try fromTable.setState(state: &state)
	}
	public func setSQL(state: inout SQLGenState) throws {
		state.currentLimit = (max, skip)
		try fromTable.setSQL(state: &state)
	}
}
