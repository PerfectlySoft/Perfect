//
//  PerfectCRUDJoin.swift
//  PerfectCRUD
//
//  Created by Kyle Jessup on 2018-01-03.
//

import Foundation

let joinPivotIdColumnName = "_crud_pivot_id_"

let joinWord = "LEFT JOIN"

public struct Join<OAF: Codable, A: TableProtocol, B: Codable, O: Equatable>: TableProtocol, FromTableProtocol, Joinable, Selectable, Whereable, Orderable, Limitable {
	public typealias Form = B
	public typealias FromTableType = A
	public typealias ComparisonType = O
	public typealias OverAllForm = OAF
	public let fromTable: FromTableType
	let to: KeyPath<OverAllForm, [Form]?>
	let on: KeyPath<OverAllForm, ComparisonType>
	let equals: KeyPath<Form, ComparisonType>
	public func setState(state: inout SQLGenState) throws {
		try fromTable.setState(state: &state)
		try state.addTable(type: Form.self, joinData: .init(to: to, on: on, equals: equals, pivot: nil))
	}
	public func setSQL(state: inout SQLGenState) throws {
		let (orderings, limit) = state.consumeState()
		try fromTable.setSQL(state: &state)
		let delegate = state.delegate
		guard let poppedTableData = state.popTableData() else {
			throw CRUDSQLGenError("No tables specified.")
		}
		let myTable = poppedTableData.myTable
		let firstTable = poppedTableData.firstTable
		let joinTables = poppedTableData.remainingTables
		let nameQ = try delegate.quote(identifier: Form.CRUDTableName)
		let aliasQ = try delegate.quote(identifier: myTable.alias)
		let fNameQ = try delegate.quote(identifier: firstTable.type.CRUDTableName)
		let fAliasQ = try delegate.quote(identifier: firstTable.alias)
		let lhsStr = try Expression.sqlSnippet(keyPath: on, tableData: firstTable, state: state)
		let rhsStr = try Expression.sqlSnippet(keyPath: equals, tableData: myTable, state: state)
		switch state.command {
		case .count:
			() // joins do nothing on .count except limit master #
		case .select:
			var sqlStr =
			"""
			SELECT DISTINCT \(aliasQ).*
			FROM \(nameQ) AS \(aliasQ)
			\(joinWord) \(fNameQ) AS \(fAliasQ) ON \(lhsStr) = \(rhsStr)

			"""
			if let whereExpr = state.whereExpr {
				let referencedTypes = whereExpr.referencedTypes()
				for type in referencedTypes {
					guard type != firstTable.type && type != Form.self else {
						continue
					}
					guard let joinTable = joinTables.first(where: { type == $0.type }) else {
						throw CRUDSQLGenError("Unknown type included in where clause \(type).")
					}
					guard let joinData = joinTable.joinData else {
						throw CRUDSQLGenError("Join without a clause \(type).")
					}
					let nameQ = try delegate.quote(identifier: joinTable.type.CRUDTableName)
					let aliasQ = try delegate.quote(identifier: joinTable.alias)
					let lhsStr = try Expression.keyPath(joinData.on).sqlSnippet(state: state)
					let rhsStr = try Expression.keyPath(joinData.equals).sqlSnippet(state: state)
					sqlStr += "\(joinWord) \(nameQ) AS \(aliasQ) ON \(lhsStr) = \(rhsStr)\n"
				}
				sqlStr += "WHERE \(try whereExpr.sqlSnippet(state: state))\n"
			}
			if !orderings.isEmpty {
				let m = try orderings.map { "\(try Expression.keyPath($0.key).sqlSnippet(state: state))\($0.desc ? " DESC" : "")" }
				sqlStr += "ORDER BY \(m.joined(separator: ", "))\n"
			}
			if let (max, skip) = limit {
				if max > 0 {
					sqlStr += "LIMIT \(max)\n"
				}
				if skip > 0 {
					sqlStr += "OFFSET \(skip)\n"
				}
			}
			state.statements.append(.init(sql: sqlStr, bindings: delegate.bindings))
			state.delegate.bindings = []
			CRUDLogging.log(.query, sqlStr)
		// ordering
		case .insert, .update, .delete:()
		//			state.fromStr.append("\(myTable)")
		case .unknown:
			throw CRUDSQLGenError("SQL command was not set.")
		}
	}
}

public struct JoinPivot<OAF: Codable, MasterTable: TableProtocol, MyForm: Codable, With: Codable, PivotCompType: Equatable, PivotCompType2: Equatable>: TableProtocol, FromTableProtocol, Joinable, Selectable, Whereable, Orderable, Limitable {
	public typealias Form = MyForm
	public typealias FromTableType = MasterTable
	public typealias PivotTableType = With
	public typealias ComparisonType = PivotCompType
	public typealias ComparisonType2 = PivotCompType2
	public typealias OverAllForm = OAF

	public let fromTable: FromTableType
	let to: KeyPath<OverAllForm, [Form]?>
	let on: KeyPath<OverAllForm, ComparisonType>
	let equals: KeyPath<PivotTableType, ComparisonType>
	let and: KeyPath<Form, ComparisonType2>
	let alsoEquals: KeyPath<PivotTableType, ComparisonType2>

	public func setState(state: inout SQLGenState) throws {
		try fromTable.setState(state: &state)
		try state.addTable(type: Form.self, joinData: .init(to: to, on: on, equals: equals, pivot: PivotTableType.self))
		try state.addTable(type: PivotTableType.self)
	}
	public func setSQL(state: inout SQLGenState) throws {
		let (orderings, limit) = state.consumeState()
		try fromTable.setSQL(state: &state)
		let delegate = state.delegate

		guard let poppedTableData1 = state.popTableData(),
			let poppedTableData2 = state.popTableData() else {
				throw CRUDSQLGenError("No tables specified.")
		}
		let myTable = poppedTableData1.myTable
		let firstTable = poppedTableData1.firstTable
		let joinTables = poppedTableData1.remainingTables
		let pivotTable = poppedTableData2.myTable

		let myNameQ = try delegate.quote(identifier: myTable.type.CRUDTableName)
		let myAliasQ = try delegate.quote(identifier: myTable.alias)

		let firstNameQ = try delegate.quote(identifier: firstTable.type.CRUDTableName)
		let firstAliasQ = try delegate.quote(identifier: firstTable.alias)

		let lhsStr = try Expression.sqlSnippet(keyPath: on, tableData: firstTable, state: state)
		let rhsStr = try Expression.sqlSnippet(keyPath: equals, tableData: pivotTable, state: state)

		let pivotNameQ = try delegate.quote(identifier: pivotTable.type.CRUDTableName)
		let pivotAliasQ = try delegate.quote(identifier: pivotTable.alias)

		let lhsStr2 = try Expression.sqlSnippet(keyPath: and, tableData: myTable, state: state)
		let rhsStr2 = try Expression.sqlSnippet(keyPath: alsoEquals, tableData: pivotTable, state: state)

		let tempColumnNameQ = try delegate.quote(identifier: joinPivotIdColumnName)

		switch state.command {
		case .count:
			() // joins do nothing on .count except limit master #
		case .select:
			var sqlStr =
			"""
			SELECT DISTINCT \(myAliasQ).*, \(lhsStr) AS \(tempColumnNameQ)
			FROM \(myNameQ) AS \(myAliasQ)
			\(joinWord) \(pivotNameQ) AS \(pivotAliasQ) ON \(lhsStr2) = \(rhsStr2)
			\(joinWord) \(firstNameQ) AS \(firstAliasQ) ON \(lhsStr) = \(rhsStr)

			"""
			if let whereExpr = state.whereExpr {
				let referencedTypes = whereExpr.referencedTypes()
				for type in referencedTypes {
					guard type != firstTable.type,
							type != Form.self,
							type != PivotTableType.self else {
						continue
					}
					guard let joinTable = joinTables.first(where: { type == $0.type }) else {
						throw CRUDSQLGenError("Unknown type included in where clause \(type).")
					}
					guard let joinData = joinTable.joinData else {
						throw CRUDSQLGenError("Join without a clause \(type).")
					}
					let nameQ = try delegate.quote(identifier: joinTable.type.CRUDTableName)
					let aliasQ = try delegate.quote(identifier: joinTable.alias)
					let lhsStr = try Expression.keyPath(joinData.on).sqlSnippet(state: state)
					let rhsStr = try Expression.keyPath(joinData.equals).sqlSnippet(state: state)
					sqlStr += "\(joinWord) \(nameQ) AS \(aliasQ) ON \(lhsStr) = \(rhsStr)\n"
				}
				sqlStr += "WHERE \(try whereExpr.sqlSnippet(state: state))\n"
			}
			if !orderings.isEmpty {
				let m = try orderings.map { "\(try Expression.keyPath($0.key).sqlSnippet(state: state))\($0.desc ? " DESC" : "")" }
				sqlStr += "ORDER BY \(m.joined(separator: ", "))\n"
			}
			if let (max, skip) = limit {
				if max > 0 {
					sqlStr += "LIMIT \(max)\n"
				}
				if skip > 0 {
					sqlStr += "OFFSET \(skip)\n"
				}
			}
			state.statements.append(.init(sql: sqlStr, bindings: delegate.bindings))
			state.delegate.bindings = []
			CRUDLogging.log(.query, sqlStr)
		// ordering
		case .insert, .update, .delete:()
		//			state.fromStr.append("\(myTable)")
		case .unknown:
			throw CRUDSQLGenError("SQL command was not set.")
		}
	}
}
