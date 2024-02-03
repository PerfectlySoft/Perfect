//
//  PerfectCRUDCodingRows.swift
//  PerfectCRUD
//
//  Created by Kyle Jessup on 2017-11-25.
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

public class CRUDRowDecoder<K: CodingKey>: Decoder {
	public typealias Key = K
	public var codingPath: [CodingKey] = []
	public var userInfo: [CodingUserInfoKey: Any] = [:]
	let delegate: SQLExeDelegate
	public init(delegate d: SQLExeDelegate) {
		delegate = d
	}
	public func container<Key>(keyedBy type: Key.Type) throws -> KeyedDecodingContainer<Key> where Key: CodingKey {
		guard let next: KeyedDecodingContainer<Key> = try delegate.next() else {
			throw CRUDDecoderError("No row.")
		}
		return next
	}
	public func unkeyedContainer() throws -> UnkeyedDecodingContainer {
		throw CRUDDecoderError("Unimplemented")
	}
	public func singleValueContainer() throws -> SingleValueDecodingContainer {
		throw CRUDDecoderError("Unimplemented")
	}
}

public class CRUDColumnValueDecoder<K: CodingKey>: Decoder, SingleValueDecodingContainer {

	public typealias Key = K
	public var codingPath: [CodingKey] = []
	public var userInfo: [CodingUserInfoKey: Any] = [:]
	// swiftlint:disable force_cast
	var key: Key { codingPath.first! as! Key }
	let source: KeyedDecodingContainer<Key>
	public init(source: KeyedDecodingContainer<Key>, key: K) {
		self.source = source
		codingPath = [key]
	}
	public func container<Key>(keyedBy type: Key.Type) throws -> KeyedDecodingContainer<Key> where Key: CodingKey {
		throw CRUDDecoderError("Unimplemented container")
	}
	public func unkeyedContainer() throws -> UnkeyedDecodingContainer {
		throw CRUDDecoderError("Unimplemented")
	}
	public func singleValueContainer() throws -> SingleValueDecodingContainer {
		return self // throw CRUDDecoderError("Unimplemented singleValueContainer")
	}

	public func decodeNil() -> Bool {
		return (try? source.decodeNil(forKey: key)) ?? false
	}

	public func decode(_ type: Bool.Type) throws -> Bool {
		return try source.decode(type, forKey: key)
	}

	public func decode(_ type: String.Type) throws -> String {
		return try source.decode(type, forKey: key)
	}

	public func decode(_ type: Double.Type) throws -> Double {
		return try source.decode(type, forKey: key)
	}

	public func decode(_ type: Float.Type) throws -> Float {
		return try source.decode(type, forKey: key)
	}

	public func decode(_ type: Int.Type) throws -> Int {
		return try source.decode(type, forKey: key)
	}

	public func decode(_ type: Int8.Type) throws -> Int8 {
		return try source.decode(type, forKey: key)
	}

	public func decode(_ type: Int16.Type) throws -> Int16 {
		return try source.decode(type, forKey: key)
	}

	public func decode(_ type: Int32.Type) throws -> Int32 {
		return try source.decode(type, forKey: key)
	}

	public func decode(_ type: Int64.Type) throws -> Int64 {
		return try source.decode(type, forKey: key)
	}

	public func decode(_ type: UInt.Type) throws -> UInt {
		return try source.decode(type, forKey: key)
	}

	public func decode(_ type: UInt8.Type) throws -> UInt8 {
		return try source.decode(type, forKey: key)
	}

	public func decode(_ type: UInt16.Type) throws -> UInt16 {
		return try source.decode(type, forKey: key)
	}

	public func decode(_ type: UInt32.Type) throws -> UInt32 {
		return try source.decode(type, forKey: key)
	}

	public func decode(_ type: UInt64.Type) throws -> UInt64 {
		return try source.decode(type, forKey: key)
	}

	public func decode<T>(_ type: T.Type) throws -> T where T: Decodable {
		return try source.decode(type, forKey: key)
	}
}

struct PivotKey<T: Codable>: Codable {
	let _crud_pivot_id_: T
}

public class CRUDPivotRowDecoder<K: CodingKey>: Decoder {
	public typealias Key = K

	public var codingPath: [CodingKey] = []
	public var userInfo: [CodingUserInfoKey: Any] = [:]
	let delegate: SQLExeDelegate
	let pivotOnType: Codable.Type
	public var orderedKeys: [Codable] = []
	public init(delegate d: SQLExeDelegate, pivotOn p: Codable.Type) {
		delegate = d
		pivotOnType = p
	}
	public func container<Key>(keyedBy type: Key.Type) throws -> KeyedDecodingContainer<Key> where Key: CodingKey {
		guard let next: KeyedDecodingContainer<ColumnKey> = try delegate.next(),
				let columnKey = ColumnKey(stringValue: joinPivotIdColumnName) else {
			throw CRUDDecoderError("No row.")
		}
		switch pivotOnType {
		case let i as Bool.Type:
			let keyValue = try next.decode(i, forKey: columnKey)
			orderedKeys.append(keyValue)
		case let i as Int.Type:
			let keyValue = try next.decode(i, forKey: columnKey)
			orderedKeys.append(keyValue)
		case let i as Int8.Type:
			let keyValue = try next.decode(i, forKey: columnKey)
			orderedKeys.append(keyValue)
		case let i as Int16.Type:
			let keyValue = try next.decode(i, forKey: columnKey)
			orderedKeys.append(keyValue)
		case let i as Int32.Type:
			let keyValue = try next.decode(i, forKey: columnKey)
			orderedKeys.append(keyValue)
		case let i as Int64.Type:
			let keyValue = try next.decode(i, forKey: columnKey)
			orderedKeys.append(keyValue)
		case let i as UInt.Type:
			let keyValue = try next.decode(i, forKey: columnKey)
			orderedKeys.append(keyValue)
		case let i as UInt8.Type:
			let keyValue = try next.decode(i, forKey: columnKey)
			orderedKeys.append(keyValue)
		case let i as UInt16.Type:
			let keyValue = try next.decode(i, forKey: columnKey)
			orderedKeys.append(keyValue)
		case let i as UInt32.Type:
			let keyValue = try next.decode(i, forKey: columnKey)
			orderedKeys.append(keyValue)
		case let i as UInt64.Type:
			let keyValue = try next.decode(i, forKey: columnKey)
			orderedKeys.append(keyValue)
		case let i as Float.Type:
			let keyValue = try next.decode(i, forKey: columnKey)
			orderedKeys.append(keyValue)
		case let i as Double.Type:
			let keyValue = try next.decode(i, forKey: columnKey)
			orderedKeys.append(keyValue)
		case let i as String.Type:
			let keyValue = try next.decode(i, forKey: columnKey)
			orderedKeys.append(keyValue)
		case let i as Date.Type:
			let keyValue = try next.decode(i, forKey: columnKey)
			orderedKeys.append(keyValue)
		case let i as Data.Type:
			let keyValue = try next.decode(i, forKey: columnKey)
			orderedKeys.append(keyValue)
		case let i as UUID.Type:
			let keyValue = try next.decode(i, forKey: columnKey)
			orderedKeys.append(keyValue)
		default:
			throw CRUDSQLExeError("Invalid join comparison type \(pivotOnType).")
		}
		return KeyedDecodingContainer(CRUDPivotRowReader(subReader: next))
	}
	public func unkeyedContainer() throws -> UnkeyedDecodingContainer {
		throw CRUDDecoderError("Unimplemented")
	}
	public func singleValueContainer() throws -> SingleValueDecodingContainer {
		throw CRUDDecoderError("Unimplemented")
	}
}

class CRUDPivotRowReader<K: CodingKey, K2: CodingKey>: KeyedDecodingContainerProtocol {
	typealias Key = K
	var codingPath: [CodingKey] = []
	var allKeys: [K] = []
	let subReader: KeyedDecodingContainer<K2>
	init(subReader s: KeyedDecodingContainer<K2>) {
		subReader = s
	}
	private func k(_ key: Key) -> K2 {
		return K2(stringValue: key.stringValue)!
	}
	func contains(_ key: K) -> Bool {
		return subReader.contains(k(key))
	}
	func decodeNil(forKey key: K) throws -> Bool {
		return try subReader.decodeNil(forKey: k(key))
	}
	func decode(_ type: Bool.Type, forKey key: K) throws -> Bool {
		return try subReader.decode(type, forKey: k(key))
	}
	func decode(_ type: Int.Type, forKey key: K) throws -> Int {
		return try subReader.decode(type, forKey: k(key))
	}
	func decode(_ type: Int8.Type, forKey key: K) throws -> Int8 {
		return try subReader.decode(type, forKey: k(key))
	}
	func decode(_ type: Int16.Type, forKey key: K) throws -> Int16 {
		return try subReader.decode(type, forKey: k(key))
	}
	func decode(_ type: Int32.Type, forKey key: K) throws -> Int32 {
		return try subReader.decode(type, forKey: k(key))
	}
	func decode(_ type: Int64.Type, forKey key: K) throws -> Int64 {
		return try subReader.decode(type, forKey: k(key))
	}
	func decode(_ type: UInt.Type, forKey key: K) throws -> UInt {
		return try subReader.decode(type, forKey: k(key))
	}
	func decode(_ type: UInt8.Type, forKey key: K) throws -> UInt8 {
		return try subReader.decode(type, forKey: k(key))
	}
	func decode(_ type: UInt16.Type, forKey key: K) throws -> UInt16 {
		return try subReader.decode(type, forKey: k(key))
	}
	func decode(_ type: UInt32.Type, forKey key: K) throws -> UInt32 {
		return try subReader.decode(type, forKey: k(key))
	}
	func decode(_ type: UInt64.Type, forKey key: K) throws -> UInt64 {
		return try subReader.decode(type, forKey: k(key))
	}
	func decode(_ type: Float.Type, forKey key: K) throws -> Float {
		return try subReader.decode(type, forKey: k(key))
	}
	func decode(_ type: Double.Type, forKey key: K) throws -> Double {
		return try subReader.decode(type, forKey: k(key))
	}
	func decode(_ type: String.Type, forKey key: K) throws -> String {
		return try subReader.decode(type, forKey: k(key))
	}
	func decode<T>(_ type: T.Type, forKey key: K) throws -> T where T: Decodable {
		return try subReader.decode(type, forKey: k(key))
	}
	func nestedContainer<NestedKey>(keyedBy type: NestedKey.Type, forKey key: K) throws -> KeyedDecodingContainer<NestedKey> where NestedKey: CodingKey {
		return try subReader.nestedContainer(keyedBy: type, forKey: k(key))
	}
	func nestedUnkeyedContainer(forKey key: K) throws -> UnkeyedDecodingContainer {
		return try subReader.nestedUnkeyedContainer(forKey: k(key))
	}
	func superDecoder() throws -> Decoder {
		return try subReader.superDecoder()
	}
	func superDecoder(forKey key: K) throws -> Decoder {
		return try subReader.superDecoder(forKey: k(key))
	}
}
