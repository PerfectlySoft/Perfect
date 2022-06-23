//
//  PerfectCRUDCodingJoinings.swift
//  PerfectCRUD
//
//  Created by Kyle Jessup on 2017-12-01.
//

import Foundation

class SQLTopRowReader<K: CodingKey>: KeyedDecodingContainerProtocol {
	typealias Key = K
	var codingPath: [CodingKey] = []
	var allKeys: [Key] = []
	let exeDelegate: SQLTopExeDelegate
	let subRowReader: KeyedDecodingContainer<K>
	init(exeDelegate e: SQLTopExeDelegate, subRowReader s: KeyedDecodingContainer<K>) {
		exeDelegate = e
		subRowReader = s
	}
	func contains(_ key: Key) -> Bool {
		return subRowReader.contains(key) || nil != exeDelegate.subObjects.index(forKey: key.stringValue)
	}
	func decodeNil(forKey key: Key) throws -> Bool {
		if nil != exeDelegate.subObjects.index(forKey: key.stringValue) {
			return false
		}
		return try subRowReader.decodeNil(forKey: key)
	}
	func decode(_ type: Bool.Type, forKey key: Key) throws -> Bool {
		return try subRowReader.decode(type, forKey: key)
	}
	func decode(_ type: Int.Type, forKey key: Key) throws -> Int {
		return try subRowReader.decode(type, forKey: key)
	}
	func decode(_ type: Int8.Type, forKey key: Key) throws -> Int8 {
		return try subRowReader.decode(type, forKey: key)
	}
	func decode(_ type: Int16.Type, forKey key: Key) throws -> Int16 {
		return try subRowReader.decode(type, forKey: key)
	}
	func decode(_ type: Int32.Type, forKey key: Key) throws -> Int32 {
		return try subRowReader.decode(type, forKey: key)
	}
	func decode(_ type: Int64.Type, forKey key: Key) throws -> Int64 {
		return try subRowReader.decode(type, forKey: key)
	}
	func decode(_ type: UInt.Type, forKey key: Key) throws -> UInt {
		return try subRowReader.decode(type, forKey: key)
	}
	func decode(_ type: UInt8.Type, forKey key: Key) throws -> UInt8 {
		return try subRowReader.decode(type, forKey: key)
	}
	func decode(_ type: UInt16.Type, forKey key: Key) throws -> UInt16 {
		return try subRowReader.decode(type, forKey: key)
	}
	func decode(_ type: UInt32.Type, forKey key: Key) throws -> UInt32 {
		return try subRowReader.decode(type, forKey: key)
	}
	func decode(_ type: UInt64.Type, forKey key: Key) throws -> UInt64 {
		return try subRowReader.decode(type, forKey: key)
	}
	func decode(_ type: Float.Type, forKey key: Key) throws -> Float {
		return try subRowReader.decode(type, forKey: key)
	}
	func decode(_ type: Double.Type, forKey key: Key) throws -> Double {
		return try subRowReader.decode(type, forKey: key)
	}
	func decode(_ type: String.Type, forKey key: Key) throws -> String {
		return try subRowReader.decode(type, forKey: key)
	}
	// main table join mechanism
	// !FIX! to put cached sub objects in foreign key dictionary
	func decode<T>(_ intype: T.Type, forKey key: Key) throws -> T where T: Decodable {
		if let (onKeyName, onKey, equalsKey, objects) = exeDelegate.subObjects[key.stringValue],
			let columnKey = Key(stringValue: onKeyName),
			let comparisonType = type(of: onKey).valueType as? Decodable.Type {

			// I could not get this to compile. because comparisonType isn't known at compile time?
			// let keyValue = try subRowReader.decode(comparisonType, forKey: columnKey)
			let theseObjs: [Any]
			switch comparisonType {
			case let i as Bool.Type:
				let keyValue = try subRowReader.decode(i, forKey: columnKey)
				theseObjs = filteredValues(objects, lhs: keyValue, rhsKey: equalsKey)
			case let i as Int.Type:
				let keyValue = try subRowReader.decode(i, forKey: columnKey)
				theseObjs = filteredValues(objects, lhs: keyValue, rhsKey: equalsKey)
			case let i as Int8.Type:
				let keyValue = try subRowReader.decode(i, forKey: columnKey)
				theseObjs = filteredValues(objects, lhs: keyValue, rhsKey: equalsKey)
			case let i as Int16.Type:
				let keyValue = try subRowReader.decode(i, forKey: columnKey)
				theseObjs = filteredValues(objects, lhs: keyValue, rhsKey: equalsKey)
			case let i as Int32.Type:
				let keyValue = try subRowReader.decode(i, forKey: columnKey)
				theseObjs = filteredValues(objects, lhs: keyValue, rhsKey: equalsKey)
			case let i as Int64.Type:
				let keyValue = try subRowReader.decode(i, forKey: columnKey)
				theseObjs = filteredValues(objects, lhs: keyValue, rhsKey: equalsKey)
			case let i as UInt.Type:
				let keyValue = try subRowReader.decode(i, forKey: columnKey)
				theseObjs = filteredValues(objects, lhs: keyValue, rhsKey: equalsKey)
			case let i as UInt8.Type:
				let keyValue = try subRowReader.decode(i, forKey: columnKey)
				theseObjs = filteredValues(objects, lhs: keyValue, rhsKey: equalsKey)
			case let i as UInt16.Type:
				let keyValue = try subRowReader.decode(i, forKey: columnKey)
				theseObjs = filteredValues(objects, lhs: keyValue, rhsKey: equalsKey)
			case let i as UInt32.Type:
				let keyValue = try subRowReader.decode(i, forKey: columnKey)
				theseObjs = filteredValues(objects, lhs: keyValue, rhsKey: equalsKey)
			case let i as UInt64.Type:
				let keyValue = try subRowReader.decode(i, forKey: columnKey)
				theseObjs = filteredValues(objects, lhs: keyValue, rhsKey: equalsKey)
			case let i as Float.Type:
				let keyValue = try subRowReader.decode(i, forKey: columnKey)
				theseObjs = filteredValues(objects, lhs: keyValue, rhsKey: equalsKey)
			case let i as Double.Type:
				let keyValue = try subRowReader.decode(i, forKey: columnKey)
				theseObjs = filteredValues(objects, lhs: keyValue, rhsKey: equalsKey)
			case let i as String.Type:
				let keyValue = try subRowReader.decode(i, forKey: columnKey)
				theseObjs = filteredValues(objects, lhs: keyValue, rhsKey: equalsKey)
			case let i as Date.Type:
				let keyValue = try subRowReader.decode(i, forKey: columnKey)
				theseObjs = filteredValues(objects, lhs: keyValue, rhsKey: equalsKey)
			case let i as Data.Type:
				let keyValue = try subRowReader.decode(i, forKey: columnKey)
				theseObjs = filteredValues(objects, lhs: keyValue, rhsKey: equalsKey)
			case let i as UUID.Type:
				let keyValue = try subRowReader.decode(i, forKey: columnKey)
				theseObjs = filteredValues(objects, lhs: keyValue, rhsKey: equalsKey)
			default:
				throw CRUDSQLExeError("Invalid join comparison type \(comparisonType).")
			}
			// swiftlint:disable force_cast
			return theseObjs as! T
		}
		return try subRowReader.decode(intype, forKey: key)
	}
	private func filteredValues<ComparisonType: Equatable>(_ values: [Any], lhs: ComparisonType, rhsKey: AnyKeyPath) -> [Any] {
		return values.compactMap {
			if let p = $0 as? PivotContainer {
				guard let rhs = p.keys.first as? ComparisonType,
					lhs == rhs else {
						return nil
				}
				return p.instance
			}
			guard let rhs = $0[keyPath: rhsKey] as? ComparisonType,
				lhs == rhs else {
					return nil
			}
			return $0
		}
	}
	func nestedContainer<NestedKey>(keyedBy type: NestedKey.Type, forKey key: Key) throws -> KeyedDecodingContainer<NestedKey> where NestedKey: CodingKey {
		return try subRowReader.nestedContainer(keyedBy: type, forKey: key)
	}
	func nestedUnkeyedContainer(forKey key: Key) throws -> UnkeyedDecodingContainer {
		return try subRowReader.nestedUnkeyedContainer(forKey: key)
	}
	func superDecoder() throws -> Decoder {
		return try subRowReader.superDecoder()
	}
	func superDecoder(forKey key: Key) throws -> Decoder {
		return try subRowReader.superDecoder(forKey: key)
	}
}
