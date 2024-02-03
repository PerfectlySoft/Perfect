//
//  TestDeleteMe.swift
//  PerfectCRUD
//
//  Created by Kyle Jessup on 2017-11-26.
//

import Foundation

public typealias Expression = CRUDExpression
public typealias Bindings = [(String, Expression)]

public protocol QueryItem {
	associatedtype OverAllForm: Codable
	func setState(state: inout SQLGenState) throws
	func setSQL(state: inout SQLGenState) throws
}

public protocol TableProtocol: QueryItem {
	associatedtype Form: Codable
	var databaseConfiguration: DatabaseConfigurationProtocol { get }
}

public protocol FromTableProtocol {
	associatedtype FromTableType: TableProtocol
	var fromTable: FromTableType { get }
}

public protocol CommandProtocol: QueryItem {
	var sqlGenState: SQLGenState { get }
}

public protocol SelectProtocol: Sequence, FromTableProtocol, CommandProtocol {
	var fromTable: FromTableType { get }
}
// swiftlint:disable class_delegate_protocol
public protocol SQLGenDelegate {
	var bindings: Bindings { get set }
	func getBinding(for: Expression) throws -> String
	func quote(identifier: String) throws -> String
	func getCreateTableSQL(forTable: TableStructure, policy: TableCreatePolicy) throws -> [String]
	func getCreateIndexSQL(forTable name: String, on columns: [String], unique: Bool) throws -> [String]
	func getEmptyInsertSnippet() -> String // usually DEFAULT VALUES vs. VALUES ()
}

public extension SQLGenDelegate {
	func getEmptyInsertSnippet() -> String {
		return "DEFAULT VALUES"
	}
}
// swiftlint:disable class_delegate_protocol
public protocol SQLExeDelegate {
	func bind(_ bindings: Bindings, skip: Int) throws
	func hasNext() throws -> Bool
	func next<A: CodingKey>() throws -> KeyedDecodingContainer<A>?
	func asyncExecute(completion: @escaping (SQLExeDelegate) -> ())
}

public protocol DatabaseConfigurationProtocol {
	var sqlGenDelegate: SQLGenDelegate { get }
	func sqlExeDelegate(forSQL: String) throws -> SQLExeDelegate

	init(url: String?, name: String?, host: String?, port: Int?, user: String?, pass: String?) throws
}

public protocol DatabaseProtocol {
	associatedtype Configuration: DatabaseConfigurationProtocol
	var configuration: Configuration { get }
	func table<T: Codable>(_ form: T.Type) -> Table<T, Self>
}

public protocol TableNameProvider {
	static var tableName: String { get }
}

public protocol Joinable: TableProtocol {
	func join<NewType: Codable, KeyType: Equatable>(_ to: KeyPath<OverAllForm, [NewType]?>, on: KeyPath<OverAllForm, KeyType>, equals: KeyPath<NewType, KeyType>) throws -> Join<OverAllForm, Self, NewType, KeyType>
}

public protocol Selectable: TableProtocol {
	func select() throws -> Select<OverAllForm, Self>
	func count() throws -> Int
}

public protocol Whereable: TableProtocol {
	func `where`(_ expr: CRUDBooleanExpression) -> Where<OverAllForm, Self>
}

public protocol Orderable: TableProtocol {
	func order(by: PartialKeyPath<Form>...) -> Ordering<OverAllForm, Self>
	func order(descending by: PartialKeyPath<Form>...) -> Ordering<OverAllForm, Self>
}

public protocol Limitable: TableProtocol {
	func limit(_ max: Int, skip: Int) -> Limit<OverAllForm, Self>
}
// swiftlint:disable line_length
public extension Joinable {
	func join<NewType: Codable, KeyType: Equatable>(_ to: KeyPath<OverAllForm, [NewType]?>, on: KeyPath<OverAllForm, KeyType>, equals: KeyPath<NewType, KeyType>) throws -> Join<OverAllForm, Self, NewType, KeyType> {
		return .init(fromTable: self, to: to, on: on, equals: equals)
	}

	func join<NewType: Codable, Pivot: Codable, FirstKeyType: Equatable, SecondKeyType: Equatable>(_ to: KeyPath<OverAllForm, [NewType]?>, with: Pivot.Type, on: KeyPath<OverAllForm, FirstKeyType>, equals: KeyPath<Pivot, FirstKeyType>, and: KeyPath<NewType, SecondKeyType>, is: KeyPath<Pivot, SecondKeyType>) throws -> JoinPivot<OverAllForm, Self, NewType, Pivot, FirstKeyType, SecondKeyType> {
		return .init(fromTable: self, to: to, on: on, equals: equals, and: and, alsoEquals: `is`)
	}
}

public extension Selectable {
	func select() throws -> Select<OverAllForm, Self> {
		return try .init(fromTable: self)
	}
	func count() throws -> Int {
		var state = SQLGenState(delegate: databaseConfiguration.sqlGenDelegate)
		state.command = .count
		try setState(state: &state)
		try setSQL(state: &state)
		guard state.statements.count == 1 else {
			throw CRUDSQLGenError("Too many statements for count().")
		}
		let stat = state.statements[0]
		let exeDelegate = try databaseConfiguration.sqlExeDelegate(forSQL: stat.sql)
		try exeDelegate.bind(stat.bindings)
		guard try exeDelegate.hasNext(),
			let container: KeyedDecodingContainer<ColumnKey> = try exeDelegate.next() else {
			throw CRUDSQLGenError("No rows returned in count().")
		}
		return try container.decode(Int.self, forKey: ColumnKey(stringValue: "count")!)
	}
	func first() throws -> OverAllForm? {
		var i = try select().makeIterator()
		return try i.nextElement()
	}
}

public extension Selectable where Self: Limitable {
	func first() throws -> OverAllForm? {
		var i = try limit(1).select().makeIterator()
		return try i.nextElement()
	}
}

public extension Whereable {
	func `where`(_ expr: CRUDBooleanExpression) -> Where<OverAllForm, Self> {
		return .init(fromTable: self, expression: expr.crudExpression)
	}
}
// swiftlint:disable line_length
public extension Orderable {
	func order(by: PartialKeyPath<Form>...) -> Ordering<OverAllForm, Self> {
		return .init(fromTable: self, keys: by, descending: false)
	}
	func order(descending by: PartialKeyPath<Form>...) -> Ordering<OverAllForm, Self> {
		return .init(fromTable: self, keys: by, descending: true)
	}
	// !FIX! Swift 4.0.2 seems to have a problem with type inference for the above two funcs
	// would not let \.name type references to be used
	// this is an ugly work around
	func order<V1: Equatable>(by: KeyPath<Form, V1>) -> Ordering<OverAllForm, Self> {
		return .init(fromTable: self, keys: [by], descending: false)
	}
	func order<V1: Equatable, V2: Equatable>(by: KeyPath<Form, V1>, _ thenBy: KeyPath<Form, V2>) -> Ordering<OverAllForm, Self> {
		return .init(fromTable: self, keys: [by, thenBy], descending: false)
	}
	func order<V1: Equatable, V2: Equatable, V3: Equatable>(by: KeyPath<Form, V1>, _ thenBy: KeyPath<Form, V2>, _ thenBy2: KeyPath<Form, V3>) -> Ordering<OverAllForm, Self> {
		return .init(fromTable: self, keys: [by, thenBy, thenBy2], descending: false)
	}
	func order<V1: Equatable, V2: Equatable, V3: Equatable, V4: Equatable>(by: KeyPath<Form, V1>, _ thenBy: KeyPath<Form, V2>, _ thenBy2: KeyPath<Form, V3>, _ thenBy3: KeyPath<Form, V4>) -> Ordering<OverAllForm, Self> {
		return .init(fromTable: self, keys: [by, thenBy, thenBy2, thenBy3], descending: false)
	}
	func order<V1: Equatable, V2: Equatable, V3: Equatable, V4: Equatable, V5: Equatable>(by: KeyPath<Form, V1>, _ thenBy: KeyPath<Form, V2>, _ thenBy2: KeyPath<Form, V3>, _ thenBy3: KeyPath<Form, V4>, _ thenBy4: KeyPath<Form, V5>) -> Ordering<OverAllForm, Self> {
		return .init(fromTable: self, keys: [by, thenBy, thenBy2, thenBy3, thenBy4], descending: false)
	}
	// desc
	func order<V1: Equatable>(descending by: KeyPath<Form, V1>) -> Ordering<OverAllForm, Self> {
		return .init(fromTable: self, keys: [by], descending: true)
	}
	func order<V1: Equatable, V2: Equatable>(descending by: KeyPath<Form, V1>, _ thenBy: KeyPath<Form, V2>) -> Ordering<OverAllForm, Self> {
		return .init(fromTable: self, keys: [by, thenBy], descending: true)
	}
	func order<V1: Equatable, V2: Equatable, V3: Equatable>(descending by: KeyPath<Form, V1>, _ thenBy: KeyPath<Form, V2>, _ thenBy2: KeyPath<Form, V3>) -> Ordering<OverAllForm, Self> {
		return .init(fromTable: self, keys: [by, thenBy, thenBy2], descending: true)
	}
	func order<V1: Equatable, V2: Equatable, V3: Equatable, V4: Equatable>(descending by: KeyPath<Form, V1>, _ thenBy: KeyPath<Form, V2>, _ thenBy2: KeyPath<Form, V3>, _ thenBy3: KeyPath<Form, V4>) -> Ordering<OverAllForm, Self> {
		return .init(fromTable: self, keys: [by, thenBy, thenBy2, thenBy3], descending: true)
	}
	func order<V1: Equatable, V2: Equatable, V3: Equatable, V4: Equatable, V5: Equatable>(descending by: KeyPath<Form, V1>, _ thenBy: KeyPath<Form, V2>, _ thenBy2: KeyPath<Form, V3>, _ thenBy3: KeyPath<Form, V4>, _ thenBy4: KeyPath<Form, V5>) -> Ordering<OverAllForm, Self> {
		return .init(fromTable: self, keys: [by, thenBy, thenBy2, thenBy3, thenBy4], descending: true)
	}
}

public extension Limitable {
	func limit(_ max: Int = 0, skip: Int = 0) -> Limit<OverAllForm, Self> {
		return .init(fromTable: self, max: max, skip: skip)
	}
	func limit(_ range: Range<Int>) -> Limit<OverAllForm, Self> {
		return limit(range.count, skip: range.lowerBound)
	}
	func limit(_ range: ClosedRange<Int>) -> Limit<OverAllForm, Self> {
		return limit(range.count, skip: range.lowerBound)
	}
	func limit(_ range: PartialRangeFrom<Int>) -> Limit<OverAllForm, Self> {
		return limit(skip: range.lowerBound)
	}
	func limit(_ range: PartialRangeThrough<Int>) -> Limit<OverAllForm, Self> {
		return limit(range.upperBound + 1)
	}
	func limit(_ range: PartialRangeUpTo<Int>) -> Limit<OverAllForm, Self> {
		return limit(range.upperBound)
	}
}

extension FromTableProtocol {
	public var databaseConfiguration: DatabaseConfigurationProtocol { return fromTable.databaseConfiguration }
}

extension CommandProtocol {
	public func setState(state: inout SQLGenState) throws {}
	public func setSQL(state: inout SQLGenState) throws {}
}

public extension SQLExeDelegate {
	func bind(_ bindings: Bindings) throws { return try bind(bindings, skip: 0) }
}

public extension Decodable {
	static var CRUDTableName: String {
		if let p = self as? TableNameProvider.Type {
			return p.tableName
		}
		return "\(Self.self)"
	}
}

struct PivotContainer {
	let instance: Codable
	let keys: [Codable]
}

struct SQLTopExeDelegate: SQLExeDelegate {
	func asyncExecute(completion: @escaping (SQLExeDelegate) -> ()) {
		// place holder
	}

	let genState: SQLGenState
	let master: (table: SQLGenState.TableData, delegate: SQLExeDelegate)
	let subObjects: [String:(onKeyName: String, onKey: AnyKeyPath, equalsKey: AnyKeyPath, objects: [Any])]
	init(genState state: SQLGenState, configurator: DatabaseConfigurationProtocol) throws {
		genState = state
		let delegates: [(table: SQLGenState.TableData, delegate: SQLExeDelegate)] = try zip(state.tableData, state.statements).map {
			let sd = try configurator.sqlExeDelegate(forSQL: $0.1.sql)
			try sd.bind($0.1.bindings)
			return ($0.0, sd)
		}
		guard !delegates.isEmpty else {
			throw CRUDSQLExeError("No tables in query.")
		}
		master = delegates[0]
		guard let modelInstance = master.table.modelInstance else {
			throw CRUDSQLExeError("No model instance for type \(master.table.type).")
		}
		let joins = delegates[1...]
		let keyPathDecoder = master.table.keyPathDecoder
		subObjects = Dictionary(uniqueKeysWithValues: try joins.map {
			let (joinTable, joinDelegate) = $0
			guard let joinData = joinTable.joinData,
				let keyStr = try keyPathDecoder.getKeyPathName(modelInstance, keyPath: joinData.to),
				let onKeyStr = try keyPathDecoder.getKeyPathName(modelInstance, keyPath: joinData.on) else {
					throw CRUDSQLExeError("No join data on \(joinTable.type)")
			}
			var ary: [Any] = []
			let joinTableType = joinTable.type
			if nil != joinData.pivot {
				guard let onType = type(of: joinData.on).valueType as? Codable.Type else {
					throw CRUDSQLExeError("Invalid join comparison type \(joinData.on).")
				}
				while try joinDelegate.hasNext() {
					let decoder = CRUDPivotRowDecoder<ColumnKey>(delegate: joinDelegate, pivotOn: onType)
					let instance = try joinTableType.init(from: decoder)
					let keys = decoder.orderedKeys
					ary.append(PivotContainer(instance: instance, keys: keys))
				}
			} else {
				while try joinDelegate.hasNext() {
					let decoder = CRUDRowDecoder<ColumnKey>(delegate: joinDelegate)
					ary.append(try joinTableType.init(from: decoder))
				}
			}
			return (keyStr, (onKeyStr, joinData.on, joinData.equals, ary))
		})
	}
	func bind(_ bindings: Bindings, skip: Int) throws {
		try master.delegate.bind(bindings, skip: skip)
	}
	func hasNext() throws -> Bool {
		return try master.delegate.hasNext()
	}
	func next<A>() throws -> KeyedDecodingContainer<A>? where A: CodingKey {
		guard let k: KeyedDecodingContainer<A> = try master.delegate.next() else {
			return nil
		}
		return KeyedDecodingContainer<A>(SQLTopRowReader(exeDelegate: self, subRowReader: k))
	}
}

public struct SQLGenState {
	public enum Command {
		case select, insert, update, delete, unknown
		case count
	}
	public struct TableData {
		public let type: Codable.Type
		public let alias: String
		public let modelInstance: Codable?
		public let keyPathDecoder: CRUDKeyPathsDecoder
		public let joinData: PropertyJoinData?
	}
	public struct PropertyJoinData {
		public let to: AnyKeyPath
		public let on: AnyKeyPath
		public let equals: AnyKeyPath
		public let pivot: Codable.Type?
	}
	public struct Statement {
		public let sql: String
		public let bindings: Bindings
	}
	struct MyTableData {
		let firstTable: TableData
		let myTable: TableData
		let remainingTables: [TableData]
	}
	typealias Ordering = (key: AnyKeyPath, desc: Bool)
	var delegate: SQLGenDelegate
	var aliasCounter = 0
	public var tableData: [TableData] = []
	var tablePopCount = 0
	public var command: Command = .unknown
	var whereExpr: Expression?
	public var statements: [Statement] = [] // statements count must match tableData count for exe to succeed
	var accumulatedOrderings: [Ordering] = []
	var currentLimit: (max: Int, skip: Int)?
	public var bindingsEncoder: CRUDBindingsEncoder?
	public var columnFilters: (include: [String], exclude: [String]) = ([], [])
	public init(delegate d: SQLGenDelegate) {
		delegate = d
	}
	mutating func consumeState() -> ([Ordering], (max: Int, skip: Int)?) {
		defer {
			accumulatedOrderings = []
			currentLimit = nil
		}
		return (accumulatedOrderings, currentLimit)
	}
	mutating func addTable<A: Codable>(type: A.Type, joinData: PropertyJoinData? = nil) throws {
		let decoder = CRUDKeyPathsDecoder()
		let model = try A(from: decoder)
		tableData.append(.init(type: type,
							   alias: nextAlias(),
							   modelInstance: model,
							   keyPathDecoder: decoder,
							   joinData: joinData))
	}
	mutating func getAlias<A: Codable>(type: A.Type) -> String? {
		return tableData.first { $0.type == type }?.alias
	}
	func getTableData(type: Any.Type) -> TableData? {
		return tableData.first { $0.type == type }
	}
	mutating func nextAlias() -> String {
		defer { aliasCounter += 1 }
		return "t\(aliasCounter)"
	}
	func getTableName<A: Codable>(type: A.Type) -> String {
		return type.CRUDTableName
	}
	mutating func getKeyName<A: Codable>(type: A.Type, key: PartialKeyPath<A>) throws -> String? {
		guard let td = getTableData(type: type),
			let instance = td.modelInstance as? A,
			let name = try td.keyPathDecoder.getKeyPathName(instance, keyPath: key) else {
				return nil
		}
		return name
	}
	mutating func popTableData() -> MyTableData? {
		guard !tableData.isEmpty else {
			return nil
		}
		let myTableIndex = tablePopCount
		tablePopCount += 1
		return MyTableData(firstTable: tableData[0],
						   myTable: tableData[myTableIndex],
						   remainingTables: myTableIndex == 0 ? Array(tableData[1...]) : Array(tableData[1..<myTableIndex]) + Array(tableData[(myTableIndex+1)...]))
	}
}

public extension Date {
	func iso8601() -> String {
		let dateFormatter = DateFormatter()
		dateFormatter.locale = Locale(identifier: "en_US_POSIX")
		dateFormatter.timeZone = TimeZone(abbreviation: "GMT")
		dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
		let ret = dateFormatter.string(from: self) + "Z"
		return ret
	}

	init?(fromISO8601 string: String) {
		let dateFormatter = DateFormatter()
		dateFormatter.locale = Locale(identifier: "en_US_POSIX")
		dateFormatter.timeZone = TimeZone.current
		let validFormats = [
			"yyyy-MM-dd'T'HH:mm:ss.SSSZ",
			"yyyy-MM-dd HH:mm:ss.SSSx",
			"yyyy-MM-dd'T'HH:mm:ssZ",
			"yyyy-MM-dd HH:mm:ssx"]
		for fmt in validFormats {
			dateFormatter.dateFormat = fmt
			if let slf = dateFormatter.date(from: string) {
				self = slf
				return
			}
		}
		return nil
	}
}

#if swift(>=4.1)
#else
// Added for Swift 4.0/4.1 compat
extension Collection {
	func compactMap<ElementOfResult>(_ transform: (Element) throws -> ElementOfResult?) rethrows -> [ElementOfResult] {
		return try flatMap(transform)
	}
}
#endif
