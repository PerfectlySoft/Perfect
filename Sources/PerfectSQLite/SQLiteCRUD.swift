//
//  SQLiteCRUD.swift
//
//  Created by Kyle Jessup on 2017-11-28.
//

import Foundation
import PerfectCRUD
// Apple platforms have SQLite3 built-in. Linux? No.
#if os(Linux)
import PerfectCSQLite3
#else
import SQLite3
#endif

public struct SQLiteCRUDError: Error, CustomStringConvertible {
	public let description: String
	init(_ m: String) {
		description = m
		CRUDLogging.log(.error, m)
	}
}

// maps column name to position which must be computed once before row reading action
typealias SQLiteCRUDColumnMap = [String: Int]

class SQLiteCRUDRowReader<K: CodingKey>: KeyedDecodingContainerProtocol {
	typealias Key = K
	var codingPath: [CodingKey] = []
	var allKeys: [Key] = []
	let database: SQLite
	let statement: SQLiteStmt
	let columns: SQLiteCRUDColumnMap
	// the SQLiteStmt has been successfully step()ed to the next row
	init(_ db: SQLite, stat: SQLiteStmt, columns cols: SQLiteCRUDColumnMap) {
		database = db
		statement = stat
		columns = cols
	}
	func columnPosition(_ key: Key) throws -> Int {
		guard let pos = columns[key.stringValue] else {
			throw CRUDDecoderError("Unrecognized key: \(key.stringValue)")
		}
		return pos
	}
	func contains(_ key: Key) -> Bool {
		return nil != columns[key.stringValue]
	}
	func decodeNil(forKey key: Key) throws -> Bool {
		return statement.isNull(position: try columnPosition(key))
	}
	func decode(_ type: Bool.Type, forKey key: Key) throws -> Bool {
		return statement.columnInt(position: try columnPosition(key)) == 1
	}
	func decode(_ type: Int.Type, forKey key: Key) throws -> Int {
		return statement.columnInt(position: try columnPosition(key))
	}
	func decode(_ type: Int8.Type, forKey key: Key) throws -> Int8 {
		return type.init(statement.columnInt(position: try columnPosition(key)))
	}
	func decode(_ type: Int16.Type, forKey key: Key) throws -> Int16 {
		return type.init(statement.columnInt(position: try columnPosition(key)))
	}
	func decode(_ type: Int32.Type, forKey key: Key) throws -> Int32 {
		return statement.columnInt32(position: try columnPosition(key))
	}
	func decode(_ type: Int64.Type, forKey key: Key) throws -> Int64 {
		return statement.columnInt64(position: try columnPosition(key))
	}
	func decode(_ type: UInt.Type, forKey key: Key) throws -> UInt {
		return type.init(statement.columnInt(position: try columnPosition(key)))
	}
	func decode(_ type: UInt8.Type, forKey key: Key) throws -> UInt8 {
		return type.init(statement.columnInt(position: try columnPosition(key)))
	}
	func decode(_ type: UInt16.Type, forKey key: Key) throws -> UInt16 {
		return type.init(statement.columnInt(position: try columnPosition(key)))
	}
	func decode(_ type: UInt32.Type, forKey key: Key) throws -> UInt32 {
		return type.init(statement.columnInt(position: try columnPosition(key)))
	}
	func decode(_ type: UInt64.Type, forKey key: Key) throws -> UInt64 {
		return type.init(statement.columnInt(position: try columnPosition(key)))
	}
	func decode(_ type: Float.Type, forKey key: Key) throws -> Float {
		return type.init(statement.columnDouble(position: try columnPosition(key)))
	}
	func decode(_ type: Double.Type, forKey key: Key) throws -> Double {
		return statement.columnDouble(position: try columnPosition(key))
	}
	func decode(_ type: String.Type, forKey key: Key) throws -> String {
		return statement.columnText(position: try columnPosition(key))
	}
	// swiftlint:disable force_cast
	func decode<T>(_ type: T.Type, forKey key: Key) throws -> T where T: Decodable {
		let position = try columnPosition(key)
		guard let special = SpecialType(type) else {
			throw CRUDDecoderError("Unsupported type: \(type) for key: \(key.stringValue)")
		}
		switch special {
		case .uint8Array:
			let ret: [UInt8] = statement.columnIntBlob(position: position)
			return ret as! T
		case .int8Array:
			let ret: [Int8] = statement.columnIntBlob(position: position)
			return ret as! T
		case .data:
			let bytes: [UInt8] = statement.columnIntBlob(position: position)
			return Data(bytes) as! T
		case .uuid:
			let str = statement.columnText(position: position)
			guard let uuid = UUID(uuidString: str) else {
				throw CRUDDecoderError("Invalid UUID string \(str).")
			}
			return uuid as! T
		case .date:
			let str = statement.columnText(position: position)
			guard let date = Date(fromISO8601: str) else {
				throw CRUDDecoderError("Invalid Date string \(str).")
			}
			return date as! T
		case .url:
			let str = statement.columnText(position: position)
			guard let url = URL(string: str) else {
				throw CRUDDecoderError("Invalid URL string \(str).")
			}
			return url as! T
		case .codable:
			guard let data = statement.columnText(position: position).data(using: .utf8) else {
				throw CRUDDecoderError("Unsupported type: \(type) for key: \(key.stringValue)")
			}
			return try JSONDecoder().decode(type, from: data)
		case .wrapped:
			let decoder = CRUDColumnValueDecoder(source: KeyedDecodingContainer(self), key: key)
			return try T(from: decoder)
		}
	}
	func nestedContainer<NestedKey>(keyedBy type: NestedKey.Type, forKey key: Key) throws -> KeyedDecodingContainer<NestedKey> where NestedKey: CodingKey {
		throw CRUDDecoderError("Unimplimented nestedContainer")
	}
	func nestedUnkeyedContainer(forKey key: Key) throws -> UnkeyedDecodingContainer {
		throw CRUDDecoderError("Unimplimented nestedUnkeyedContainer")
	}
	func superDecoder() throws -> Decoder {
		throw CRUDDecoderError("Unimplimented superDecoder")
	}
	func superDecoder(forKey key: Key) throws -> Decoder {
		throw CRUDDecoderError("Unimplimented superDecoder")
	}
}

struct SQLiteColumnInfo: Codable {
	let cid: Int
	let name: String
	let type: String
	let notnull: Int
	let dflt_value: String
	let pk: Bool
}

class SQLiteGenDelegate: SQLGenDelegate {
	let database: SQLite
	var parentTableStack: [TableStructure] = []
	var bindings: Bindings = []
	var extraCreate: [String] = []

	init(_ db: SQLite) {
		database = db
	}
	// swiftlint:disable opening_brace
	func getCreateIndexSQL(forTable name: String, on columns: [String], unique: Bool) throws -> [String] {
		let stat =
		"""
		CREATE \(unique ? "UNIQUE " : "")INDEX IF NOT EXISTS \(try quote(identifier: "index_\(columns.joined(separator: "_"))"))
		ON \(try quote(identifier: name)) (\(try columns.map{try quote(identifier: $0)}.joined(separator: ",")))
		"""
		return [stat]
	}

	func getCreateTableSQL(forTable: TableStructure, policy: TableCreatePolicy) throws -> [String] {
		parentTableStack.append(forTable)
		defer {
			parentTableStack.removeLast()
		}
		var sub: [String] = []
		if policy.contains(.dropTable) {
			sub += ["DROP TABLE IF EXISTS \(try quote(identifier: forTable.tableName))"]
		}
		if !policy.contains(.dropTable),
				policy.contains(.reconcileTable),
				let existingColumns = getExistingColumnData(forTable: forTable.tableName),
				!existingColumns.isEmpty {
			let existingColumnMap: [String: SQLiteColumnInfo] = .init(uniqueKeysWithValues: existingColumns.map { ($0.name, $0) })
			let newColumnMap: [String: TableStructure.Column] = .init(uniqueKeysWithValues: forTable.columns.map { ($0.name, $0) })

			let addColumns = newColumnMap.keys.filter { existingColumnMap[$0] == nil }
			let removeColumns: [String] = existingColumnMap.keys.filter { newColumnMap[$0] == nil }

			if !removeColumns.isEmpty {
				let nameQ = try quote(identifier: forTable.tableName)
				let tempNameQ = try quote(identifier: "temp_\(forTable.tableName)_temp")
				let sharedColumns = existingColumns.map { $0.name }.filter { !removeColumns.contains($0) }
				sub += [ // sqlite does not have 'drop column'
					"ALTER TABLE \(nameQ) RENAME TO \(tempNameQ)",
					"""
					CREATE TABLE IF NOT EXISTS \(nameQ) (
					\(try forTable.columns.map { try getColumnDefinition($0) }.joined(separator: ",\n\t"))
					)
					""",
					"""
					INSERT INTO \(nameQ) (\(sharedColumns.joined(separator: ",")))
					SELECT \(sharedColumns.joined(separator: ","))
					FROM \(tempNameQ)
					""",
					"DROP TABLE \(tempNameQ)"
				]
			} else {
				sub += try addColumns.compactMap { newColumnMap[$0] }.map {
					let nameType = try getColumnDefinition($0)
					return """
					ALTER TABLE \(try quote(identifier: forTable.tableName)) ADD COLUMN \(nameType)
					"""
				}
			}
			return sub
		} else {
			sub += [
			"""
			CREATE TABLE IF NOT EXISTS \(try quote(identifier: forTable.tableName)) (
				\((try forTable.columns.map { try getColumnDefinition($0) } + extraCreate).joined(separator: ",\n\t"))
			)
			"""]
		}
		if !policy.contains(.shallow) {
			sub += try forTable.subTables.flatMap {
				try getCreateTableSQL(forTable: $0, policy: policy)
			}
		}
		return sub
	}

	func getExistingColumnData(forTable: String) -> [SQLiteColumnInfo]? {
		do {
			let prep = try database.prepare(statement: "PRAGMA table_info(\"\(forTable)\")")
			let exeDelegate = SQLiteExeDelegate(database, stat: prep)
			var ret: [SQLiteColumnInfo] = []
			while try exeDelegate.hasNext() {
				let rowDecoder = CRUDRowDecoder<ColumnKey>(delegate: exeDelegate)
				ret.append(try SQLiteColumnInfo(from: rowDecoder))
			}
			return ret
		} catch {
			return nil
		}
	}
	private func getTypeName(_ type: Any.Type) throws -> String {
		let typeName: String
		switch type {
		case is Int.Type:
			typeName = "INT"
		case is Int8.Type:
			typeName = "INT"
		case is Int16.Type:
			typeName = "INT"
		case is Int32.Type:
			typeName = "INT"
		case is Int64.Type:
			typeName = "INT"
		case is UInt.Type:
			typeName = "INT"
		case is UInt8.Type:
			typeName = "INT"
		case is UInt16.Type:
			typeName = "INT"
		case is UInt32.Type:
			typeName = "INT"
		case is UInt64.Type:
			typeName = "INT"
		case is Double.Type:
			typeName = "REAL"
		case is Float.Type:
			typeName = "REAL"
		case is Bool.Type:
			typeName = "INT"
		case is String.Type:
			typeName = "TEXT"
		default:
			guard let special = SpecialType(type) else {
				throw SQLiteCRUDError("Unsupported SQL column type \(type)")
			}
			switch special {
			case .uint8Array:
				typeName = "BLOB"
			case .int8Array:
				typeName = "BLOB"
			case .data:
				typeName = "BLOB"
			case .uuid:
				typeName = "TEXT"
			case .date:
				typeName = "TEXT"
			case .url:
				typeName = "TEXT"
			case .codable:
				typeName = "TEXT"
			case .wrapped:
				guard let w = type as? WrappedCodableProvider.Type else {
					throw SQLiteCRUDError("Unsupported SQL column type \(type)")
				}
				return try getTypeName(w)
			}
		}
		return typeName
	}
	func getColumnDefinition(_ column: TableStructure.Column) throws -> String {
		let name = column.name
		let type = column.type
		let typeName = try getTypeName(type)
		var addendum = ""
		for prop in column.properties {
			switch prop {
			case .primaryKey:
				addendum += " PRIMARY KEY"
			case .foreignKey(let table, let column, let onDelete, let onUpdate):
				var str = "FOREIGN KEY(\(name)) REFERENCES \(table)(\(column))"
				let scenarios = [(" ON DELETE ", onDelete), (" ON UPDATE ", onUpdate)]
				for (scenario, action) in scenarios {
					str += scenario
					switch action {
					case .ignore:
						str += "NO ACTION"
					case .restrict:
						str += "RESTRICT"
					case .setNull:
						str += "SET NULL"
					case .setDefault:
						str += "SET DEFAULT"
					case .cascade:
						str += "CASCADE"
					}
				}
				extraCreate.append(str)
			}
		}
		if !column.properties.contains(.primaryKey) && !column.optional {
			addendum += " NOT NULL"
		}
		return "\(name) \(typeName)\(addendum)"
	}
	func getBinding(for expr: Expression) throws -> String {
		bindings.append(("?", expr))
		return "?"
	}
	func quote(identifier: String) throws -> String {
		return "\"\(identifier)\""
	}
}

// maps column name to position which must be computed once before row reading action
typealias SQLiteColumnMap = [String: Int]

class SQLiteExeDelegate: SQLExeDelegate {
	let database: SQLite
	let statement: SQLiteStmt
	let columnMap: SQLiteColumnMap
	init(_ db: SQLite, stat: SQLiteStmt) {
		database = db
		statement = stat
		var m = SQLiteColumnMap()
		let count = statement.columnCount()
		for i in 0..<count {
			let name = statement.columnName(position: i)
			m[name] = i
		}
		columnMap = m
	}
	func bind(_ binds: Bindings, skip: Int) throws {
		_ = try statement.reset()
		var i = skip + 1
		try binds[skip...].forEach {
			let (_, expr) = $0
			try bindOne(position: i, expr: expr)
			i += 1
		}
	}
	func hasNext() throws -> Bool {
		let step = statement.step()
		guard step == SQLITE_ROW || step == SQLITE_DONE else {
			throw SQLiteCRUDError(database.errMsg())
		}
		return step == SQLITE_ROW
	}
	func next<A>() -> KeyedDecodingContainer<A>? where A: CodingKey {
		return KeyedDecodingContainer(SQLiteCRUDRowReader<A>(database, stat: statement, columns: columnMap))
	}
	func asyncExecute(completion: @escaping (SQLExeDelegate) -> ()) {
		completion(self)
	}
	private func bindOne(position: Int, expr: CRUDExpression) throws {
		switch expr {
		case .lazy(let e):
			try bindOne(position: position, expr: e())
		case .decimal(let d):
			try statement.bind(position: position, d)
		case .string(let s):
			try statement.bind(position: position, s)
		case .blob(let b):
			try statement.bind(position: position, b)
		case .bool(let b):
			try statement.bind(position: position, b ? 1 : 0)
		case .null:
			try statement.bindNull(position: position)
		case .date(let d):
			try statement.bind(position: position, d.iso8601())
		case .url(let u):
			try statement.bind(position: position, u.absoluteString)
		case .uuid(let u):
			try statement.bind(position: position, u.uuidString)
		case .column(_), .and(_, _), .or(_, _),
			 .equality(_, _), .inequality(_, _),
			 .not(_), .lessThan(_, _), .lessThanEqual(_, _),
			 .greaterThan(_, _), .greaterThanEqual(_, _),
			 .keyPath(_), .in(_, _), .like(_, _, _, _):
			throw SQLiteCRUDError("Asked to bind unsupported expression type: \(expr)")
		case .integer(let i):
			try statement.bind(position: position, i)
		case .uinteger(let i):
			try statement.bind(position: position, Int(i))
		case .integer64(let i):
			try statement.bind(position: position, Int(i))
		case .uinteger64(let i):
			try statement.bind(position: position, Int(i))
		case .integer32(let i):
			try statement.bind(position: position, Int(i))
		case .uinteger32(let i):
			try statement.bind(position: position, Int(i))
		case .integer16(let i):
			try statement.bind(position: position, Int(i))
		case .uinteger16(let i):
			try statement.bind(position: position, Int(i))
		case .integer8(let i):
			try statement.bind(position: position, Int(i))
		case .uinteger8(let i):
			try statement.bind(position: position, Int(i))
		case .float(let d):
			try statement.bind(position: position, Double(d))
		case .sblob(let b):
			try statement.bind(position: position, b.map{UInt8(bitPattern: $0)})
		}
	}
}

public struct SQLiteDatabaseConfiguration: DatabaseConfigurationProtocol {
	public var sqlGenDelegate: SQLGenDelegate {
		return SQLiteGenDelegate(sqlite)
	}
	public func sqlExeDelegate(forSQL sql: String) throws -> SQLExeDelegate {
		let prep = try sqlite.prepare(statement: sql)
		return SQLiteExeDelegate(sqlite, stat: prep)
	}
	public let name: String
	public let sqlite: SQLite
	public init(_ n: String, _ pragmas: [String] = ["PRAGMA foreign_keys = ON"]) throws {
		name = n
		sqlite = try SQLite(n)
		for pragma in pragmas {
			try sqlite.execute(statement: pragma)
		}
	}
	public init(url: String?, name: String?, host: String?, port: Int?, user: String?, pass: String?) throws {
		guard let n = name else {
			throw SQLiteCRUDError("Database name must be provided.")
		}
		try self.init(n)
	}
}

public extension Insert {
	func lastInsertId() throws -> Int? {
		let exeDelegate = try databaseConfiguration.sqlExeDelegate(forSQL: "SELECT last_insert_rowid()")
		guard try exeDelegate.hasNext(), let next: KeyedDecodingContainer<ColumnKey> = try exeDelegate.next() else {
			throw CRUDSQLGenError("Did not get return value from statement \"SELECT last_insert_rowid()\".")
		}
		let value = try next.decode(Int.self, forKey: ColumnKey(stringValue: "last_insert_rowid()")!)
		return value
	}
}
