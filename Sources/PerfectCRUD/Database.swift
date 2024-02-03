//
//  PerfectCRUDDatabase.swift
//  PerfectCRUD
//
//  Created by Kyle Jessup on 2017-12-02.
//

import Foundation

public struct Database<C: DatabaseConfigurationProtocol>: DatabaseProtocol {
	public typealias Configuration = C
	public let configuration: Configuration
	public init(configuration c: Configuration) {
		configuration = c
	}
	public func table<T: Codable>(_ form: T.Type) -> Table<T, Database> {
		return .init(database: self)
	}
}

public extension Database {
	func sql(_ sql: String, bindings: Bindings = []) throws {
		CRUDLogging.log(.query, sql)
		let delegate = try configuration.sqlExeDelegate(forSQL: sql)
		try delegate.bind(bindings, skip: 0)
		_ = try delegate.hasNext()
	}
	func sql<A: Codable>(_ sql: String, bindings: Bindings = [], _ type: A.Type) throws -> [A] {
		CRUDLogging.log(.query, sql)
		let delegate = try configuration.sqlExeDelegate(forSQL: sql)
		try delegate.bind(bindings, skip: 0)
		var ret: [A] = []
		while try delegate.hasNext() {
			let rowDecoder: CRUDRowDecoder<ColumnKey> = CRUDRowDecoder(delegate: delegate)
			ret.append(try A(from: rowDecoder))
		}
		return ret
	}
	func asyncSql<A: Codable>(_ sql: String, bindings: Bindings = [], _ type: A.Type, completion: @escaping ([A], Error?) -> ()) throws {
		CRUDLogging.log(.query, sql)
		let delegate = try configuration.sqlExeDelegate(forSQL: sql)
		try delegate.bind(bindings, skip: 0)
		delegate.asyncExecute { delegate in
			var ret: [A] = []
			do {
				while try delegate.hasNext() {
					let rowDecoder: CRUDRowDecoder<ColumnKey> = CRUDRowDecoder(delegate: delegate)
					ret.append(try A(from: rowDecoder))
				}
				completion(ret, nil)
			} catch {
				completion(ret, error)
			}
		}
	}
}

public extension Database {
	func transaction<T>(_ body: () throws -> T) throws -> T {
		try sql("BEGIN")
		do {
			let r = try body()
			try sql("COMMIT")
			return r
		} catch {
			try sql("ROLLBACK")
			throw error
		}
	}
}
