//
//  PerfectCRUDExpressions.swift
//  PerfectCRUD
//
//  Created by Kyle Jessup on 2017-11-22.
//	Copyright (C) 2017 PerfectlySoft, Inc.
//
// ===----------------------------------------------------------------------===//
//
// This source file is part of the Perfect.org open source project
//
// Copyright (c) 2015 - 2017 PerfectlySoft Inc. and the Perfect project authors
// Licensed under Apache License v2.0
//
// See http://perfect.org/licensing.html for license information
//
// ===----------------------------------------------------------------------===//
//
import Foundation

public indirect enum CRUDExpression {
	public typealias ExpressionProducer = () -> CRUDExpression

	case column(String)
	case and(lhs: CRUDExpression, rhs: CRUDExpression)
	case or(lhs: CRUDExpression, rhs: CRUDExpression)
	case equality(lhs: CRUDExpression, rhs: CRUDExpression)
	case inequality(lhs: CRUDExpression, rhs: CRUDExpression)
	case not(rhs: CRUDExpression)
	case lessThan(lhs: CRUDExpression, rhs: CRUDExpression)
	case lessThanEqual(lhs: CRUDExpression, rhs: CRUDExpression)
	case greaterThan(lhs: CRUDExpression, rhs: CRUDExpression)
	case greaterThanEqual(lhs: CRUDExpression, rhs: CRUDExpression)
	case `in`(lhs: CRUDExpression, rhs: [CRUDExpression])
	case like(lhs: CRUDExpression, wild1: Bool, String, wild2: Bool)
	case lazy(ExpressionProducer)
	case keyPath(AnyKeyPath)

	case integer(Int)
	case uinteger(UInt)
	case integer64(Int64)
	case uinteger64(UInt64)
	case integer32(Int32)
	case uinteger32(UInt32)
	case integer16(Int16)
	case uinteger16(UInt16)
	case integer8(Int8)
	case uinteger8(UInt8)

	case decimal(Double)
	case float(Float)
	case string(String)
	case blob([UInt8])
	case sblob([Int8])
	case bool(Bool)
	case uuid(UUID)
	case date(Date)
	case url(URL)
	case null

	// todo:
	// .blob with Data
	// .integer of varying width
}

public protocol CRUDBooleanExpression {
	var crudExpression: CRUDExpression { get }
}

struct RealBooleanExpression: CRUDBooleanExpression {
	let crudExpression: CRUDExpression
	init(_ e: CRUDExpression) {
		crudExpression = e
	}
}

infix operator ~: ComparisonPrecedence // IN, matches
infix operator !~: ComparisonPrecedence // NOT IN, matches
infix operator %=%: ComparisonPrecedence // LIKE %v% . string or regexp or in array
infix operator =%: ComparisonPrecedence // LIKE v% . string
infix operator %!=: ComparisonPrecedence // NOT LIKE %v . string
infix operator %!=%: ComparisonPrecedence // NOT LIKE %v% . string or regexp or array
infix operator !=%: ComparisonPrecedence // NOT LIKE v% . string

extension CRUDExpression {
	static func sqlSnippet(keyPath: AnyKeyPath, tableData: SQLGenState.TableData, state: SQLGenState) throws -> String {
		let delegate = state.delegate
		let rootType = type(of: keyPath).rootType
		guard let modelInstance = tableData.modelInstance else {
				throw CRUDSQLGenError("Unable to get table for KeyPath root \(rootType).")
		}
		guard let keyName = try tableData.keyPathDecoder.getKeyPathName(modelInstance, keyPath: keyPath) else {
			throw CRUDSQLGenError("Unable to get KeyPath name for table \(rootType).")
		}
		let nameQ = try delegate.quote(identifier: keyName)
		switch state.command {
		case .select, .count:
			let aliasQ = try delegate.quote(identifier: tableData.alias)
			return "\(aliasQ).\(nameQ)"
		case .insert, .update, .delete:
			return nameQ
		case .unknown:
			throw CRUDSQLGenError("Can not process unknown command.")
		}
	}
	func sqlSnippet(state: SQLGenState) throws -> String {
		let delegate = state.delegate
		switch self {
		case .column(let name):
			return try delegate.quote(identifier: name)
		case .and(let lhs, let rhs):
			return try binparen(state, "AND", lhs, rhs)
		case .or(let lhs, let rhs):
			return try binparen(state, "OR", lhs, rhs)
		case .equality(let lhs, let rhs):
			if case .null = rhs {
				return "\(try lhs.sqlSnippet(state: state)) IS NULL"
			}
			return try bin(state, "=", lhs, rhs)
		case .inequality(let lhs, let rhs):
			if case .null = rhs {
				return "\(try lhs.sqlSnippet(state: state)) IS NOT NULL"
			}
			return try bin(state, "!=", lhs, rhs)
		case .not(let rhs):
			let rhsStr = try rhs.sqlSnippet(state: state)
			return "NOT (\(rhsStr))"
		case .lessThan(let lhs, let rhs):
			return try bin(state, "<", lhs, rhs)
		case .lessThanEqual(let lhs, let rhs):
			return try bin(state, "<=", lhs, rhs)
		case .greaterThan(let lhs, let rhs):
			return try bin(state, ">", lhs, rhs)
		case .greaterThanEqual(let lhs, let rhs):
			return try bin(state, ">=", lhs, rhs)
		case .keyPath(let k):
			let rootType = type(of: k).rootType
			guard let tableData = state.getTableData(type: rootType) else {
				throw CRUDSQLGenError("Unable to get table for KeyPath root \(rootType).")
			}
			return try CRUDExpression.sqlSnippet(keyPath: k, tableData: tableData, state: state)
		case .null:
			return "NULL"
		case .lazy(let e):
			return try e().sqlSnippet(state: state)
		case .integer(_), .uinteger(_), .integer64(_), .uinteger64(_), .integer32(_), .uinteger32(_), .integer16(_), .uinteger16(_), .integer8(_), .uinteger8(_):
			return try delegate.getBinding(for: self)
		case .decimal(_), .float(_), .string(_), .blob(_), .sblob(_), .bool(_), .uuid(_), .date(_), .url(_):
			return try delegate.getBinding(for: self)
		case .in(let lhs, let exprs):
			return "\(try lhs.sqlSnippet(state: state)) IN (\(try exprs.map { try $0.sqlSnippet(state: state) }.joined(separator: ",")))"
		case .like(let lhs, let wild1, let match, let wild2):
			let rhs = "\(wild1 ? "%" : "")\(match.replacingOccurrences(of: "%", with: "\\%"))\(wild2 ? "%" : "")"
			return try bin(state, "LIKE", lhs, .string(rhs))
		}
	}
	private func bin(_ state: SQLGenState, _ op: String, _ lhs: CRUDExpression, _ rhs: CRUDExpression) throws -> String {
		return "\(try lhs.sqlSnippet(state: state)) \(op) \(try rhs.sqlSnippet(state: state))"
	}
	private func binparen(_ state: SQLGenState, _ op: String, _ lhs: CRUDExpression, _ rhs: CRUDExpression) throws -> String {
		return "(\(try lhs.sqlSnippet(state: state)) \(op) \(try rhs.sqlSnippet(state: state)))"
	}
	private func un(_ state: SQLGenState, _ op: String, _ rhs: CRUDExpression) throws -> String {
		return "\(op) \(try rhs.sqlSnippet(state: state))"
	}
	func referencedTypes() -> [Any.Type] {
		switch self {
		case .column(_):
			return []
		case .and(let lhs, let rhs):
			return lhs.referencedTypes() + rhs.referencedTypes()
		case .or(let lhs, let rhs):
			return lhs.referencedTypes() + rhs.referencedTypes()
		case .equality(let lhs, let rhs):
			return lhs.referencedTypes() + rhs.referencedTypes()
		case .inequality(let lhs, let rhs):
			return lhs.referencedTypes() + rhs.referencedTypes()
		case .not(let rhs):
			return rhs.referencedTypes()
		case .lessThan(let lhs, let rhs):
			return lhs.referencedTypes() + rhs.referencedTypes()
		case .lessThanEqual(let lhs, let rhs):
			return lhs.referencedTypes() + rhs.referencedTypes()
		case .greaterThan(let lhs, let rhs):
			return lhs.referencedTypes() + rhs.referencedTypes()
		case .greaterThanEqual(let lhs, let rhs):
			return lhs.referencedTypes() + rhs.referencedTypes()
		case .keyPath(let k):
			return [type(of: k).rootType]
		case .null:
			return []
		case .lazy(let e):
			return e().referencedTypes()
		case .integer(_), .uinteger(_), .integer64(_), .uinteger64(_), .integer32(_), .uinteger32(_), .integer16(_), .uinteger16(_), .integer8(_), .uinteger8(_):
			return []
		case .decimal(_), .float(_), .string(_), .blob(_), .sblob(_), .bool(_), .uuid(_), .date(_), .url(_):
			return []
		case .in(let lhs, let exprs):
			return lhs.referencedTypes() + exprs.flatMap { $0.referencedTypes() }
		case .like(let lhs, _, _, _):
			return lhs.referencedTypes()
		}
	}
}
