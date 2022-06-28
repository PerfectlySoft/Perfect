//
//  PerfectCRUDCodingNames.swift
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

// -- reads and records the coding keys for an object
class CRUDColumnNamesReader<K: CodingKey>: KeyedDecodingContainerProtocol {
	typealias Key = K
	var codingPath: [CodingKey] = []

	var allKeys: [Key] = []
	var parent: CRUDColumnNameDecoder
	var knownKeys = Set<String>()
	var isOptional = false
	init(_ p: CRUDColumnNameDecoder) {
		parent = p
	}
	func appendKey(_ key: Key, _ type: Any.Type) {
		let s = key.stringValue
		if !knownKeys.contains(s) {
			parent.collectedKeys.append((s, isOptional, type))
			knownKeys.insert(s)
		}
		isOptional = false // reset
	}
	func contains(_ key: Key) -> Bool {
		return true
	}
	func decodeNil(forKey key: Key) throws -> Bool {
		isOptional = true
		return false
	}
	func decode(_ type: Bool.Type, forKey key: Key) throws -> Bool {
		appendKey(key, type)
		return true
	}
	func decode(_ type: Int.Type, forKey key: Key) throws -> Int {
		appendKey(key, type)
		return 0
	}
	func decode(_ type: Int8.Type, forKey key: Key) throws -> Int8 {
		appendKey(key, type)
		return 0
	}
	func decode(_ type: Int16.Type, forKey key: Key) throws -> Int16 {
		appendKey(key, type)
		return 0
	}
	func decode(_ type: Int32.Type, forKey key: Key) throws -> Int32 {
		appendKey(key, type)
		return 0
	}
	func decode(_ type: Int64.Type, forKey key: Key) throws -> Int64 {
		appendKey(key, type)
		return 0
	}
	func decode(_ type: UInt.Type, forKey key: Key) throws -> UInt {
		appendKey(key, type)
		return 0
	}
	func decode(_ type: UInt8.Type, forKey key: Key) throws -> UInt8 {
		appendKey(key, type)
		return 0
	}
	func decode(_ type: UInt16.Type, forKey key: Key) throws -> UInt16 {
		appendKey(key, type)
		return 0
	}
	func decode(_ type: UInt32.Type, forKey key: Key) throws -> UInt32 {
		appendKey(key, type)
		return 0
	}
	func decode(_ type: UInt64.Type, forKey key: Key) throws -> UInt64 {
		appendKey(key, type)
		return 0
	}
	func decode(_ type: Float.Type, forKey key: Key) throws -> Float {
		appendKey(key, type)
		return 0
	}
	func decode(_ type: Double.Type, forKey key: Key) throws -> Double {
		appendKey(key, type)
		return 0
	}
	func decode(_ type: String.Type, forKey key: Key) throws -> String {
		appendKey(key, type)
		return ""
	}
	// swiftlint:disable force_cast
	func decode<T: Decodable>(_ t: T.Type, forKey key: Key) throws -> T {
		if let special = SpecialType(t) {
			switch special {
			case .uint8Array:
				appendKey(key, t)
				return [UInt8]() as! T
			case .int8Array:
				appendKey(key, t)
				return [Int8]() as! T
			case .data:
				appendKey(key, t)
				return Data() as! T
			case .uuid:
				appendKey(key, t)
				return UUID() as! T
			case .date:
				appendKey(key, t)
				return Date() as! T
			case .url:
				appendKey(key, t)
				return URL(string: "http://localhost")! as! T
			case .codable:
				()
			case .wrapped:
				()
//				guard let wrapped = t as? WrappedCodableProvider.Type else {
//					throw CRUDEncoderError("Unsupported decoding type: \(t) for key: \(key.stringValue)")
//				}
//				let wrappedValueType = wrapped.provideWrappedValueType()
//				switch wrappedValueType {
//				case let m as Bool.Type: return try decode(m, forKey: key)
//				case let m as Int.Type: return try decode(m, forKey: key)
//				case let m as Int8.Type: return try decode(m, forKey: key)
//				case let m as Int16.Type: return try decode(m, forKey: key)
//				case let m as Int32.Type: return try decode(m, forKey: key)
//				case let m as Int64.Type: return try decode(m, forKey: key)
//				case let m as UInt.Type: return try decode(m, forKey: key)
//				case let m as UInt8.Type: return try decode(m, forKey: key)
//				case let m as UInt16.Type: return try decode(m, forKey: key)
//				case let m as UInt32.Type: return try decode(m, forKey: key)
//				case let m as UInt64.Type: return try decode(m, forKey: key)
//				case let m as Float.Type: return try decode(m, forKey: key)
//				case let m as Double.Type: return try decode(m, forKey: key)
//				case let m as String.Type: return try decode(m, forKey: key)
//				default:
//					throw CRUDEncoderError("Unsupported decoding type: wrapped(\(wrappedValueType)) for key: \(key.stringValue)")
//				}
			}
		}
		return try decodeInner(t, forKey: key)
	}

	func decodeInner<T: Decodable>(_ t: T.Type, forKey key: Key) throws -> T {
		let sub = CRUDColumnNameDecoder(depth: 1 + parent.depth)
		let ret = try T(from: sub)
		if let ar = ret as? [Codable] {
			if !ar.isEmpty {
				let subType = type(of: ar[0])
				sub.codingPath.append(key)
				sub.tableNamePath.append(subType.CRUDTableName)
				ar[0].addSubTable(to: parent, name: key.stringValue, decoder: sub)
			}
			return ret
//		} else if ret is WrappedValueTypeProvider {
//			appendKey(key, type(of: ret as! WrappedValueTypeProvider).wrappedValueType())
//			return ret
		} else if ret is Codable { // ...
			appendKey(key, type(of: ret))
			return ret
		}
		throw CRUDSQLGenError("Unsupported sub-table type \(T.self)")
	}

	func nestedContainer<NestedKey: CodingKey>(keyedBy type: NestedKey.Type, forKey key: Key) throws -> KeyedDecodingContainer<NestedKey> {
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

class CRUDColumnNameUnkeyedReader: UnkeyedDecodingContainer, SingleValueDecodingContainer {
	let codingPath: [CodingKey] = []
	var count: Int? = 1
	var isAtEnd: Bool { return !(currentIndex < count ?? 0) }
	var currentIndex: Int = 0
	let parent: CRUDColumnNameDecoder
	var decodedType: Any.Type?
	var typeDecoder: CRUDColumnNameDecoder?
	init(parent p: CRUDColumnNameDecoder) {
		parent = p
	}
	func advance(_ t: Any.Type) {
		currentIndex += 1
		decodedType = t
	}
	func decodeNil() -> Bool {
		return false
	}

	func decode(_ type: Bool.Type) throws -> Bool {
		advance(type)
		return false
	}

	func decode(_ type: Int.Type) throws -> Int {
		advance(type)
		return 0
	}

	func decode(_ type: Int8.Type) throws -> Int8 {
		advance(type)
		return 0
	}

	func decode(_ type: Int16.Type) throws -> Int16 {
		advance(type)
		return 0
	}

	func decode(_ type: Int32.Type) throws -> Int32 {
		advance(type)
		return 0
	}

	func decode(_ type: Int64.Type) throws -> Int64 {
		advance(type)
		return 0
	}

	func decode(_ type: UInt.Type) throws -> UInt {
		advance(type)
		return 0
	}

	func decode(_ type: UInt8.Type) throws -> UInt8 {
		advance(type)
		return 0
	}

	func decode(_ type: UInt16.Type) throws -> UInt16 {
		advance(type)
		return 0
	}

	func decode(_ type: UInt32.Type) throws -> UInt32 {
		advance(type)
		return 0
	}
	func decode(_ type: UInt64.Type) throws -> UInt64 {
		advance(type)
		return 0
	}
	func decode(_ type: Float.Type) throws -> Float {
		advance(type)
		return 0
	}
	func decode(_ type: Double.Type) throws -> Double {
		advance(type)
		return 0
	}
	func decode(_ type: String.Type) throws -> String {
		advance(type)
		return ""
	}
	// swiftlint:disable force_cast
	func decode<T: Decodable>(_ t: T.Type) throws -> T {
		advance(t)
		if let special = SpecialType(t) {
			switch special {
			case .uint8Array:
				return [UInt8]() as! T
			case .int8Array:
				return [Int8]() as! T
			case .data:
				return Data() as! T
			case .uuid:
				return UUID() as! T
			case .date:
				return Date() as! T
			case .url:
				return URL(string: "http://localhost")! as! T
			case .codable, .wrapped:
				()
			}
		}
		return try T(from: parent)
	}
	func nestedContainer<NestedKey: CodingKey>(keyedBy type: NestedKey.Type) throws -> KeyedDecodingContainer<NestedKey> {
		throw CRUDDecoderError("Unimplimented nestedContainer")
	}
	func nestedUnkeyedContainer() throws -> UnkeyedDecodingContainer {
		throw CRUDDecoderError("Unimplimented nestedUnkeyedContainer")
	}
	func superDecoder() throws -> Decoder {
		currentIndex += 1
		return parent
	}
}

protocol SubTableProto {
	var name: String { get }
//	var type: Decodable.Type { get }
//	var decoder: CRUDColumnNameDecoder { get }
	func tableStructure() throws -> TableStructure
	func matches<T: Decodable>(_ type: T.Type) -> Bool
}

struct SubTable<T: Decodable, R: Decodable>: SubTableProto {
	let name: String
	let type: T.Type
	let decoder: CRUDColumnNameDecoder
	let realType: R.Type
	func tableStructure() throws -> TableStructure {
		return try type.self.CRUDTableStructure(columnDecoder: decoder)
	}
	func matches<T: Decodable>(_ type: T.Type) -> Bool {
		return self.type == type
	}
}

extension Decodable where Self: Encodable {
    @available(macOS 10.15.0, *)
    func makeSubTable(name: String, decoder: CRUDColumnNameDecoder) -> some SubTableProto {
		return SubTable(name: name, type: Self.self, decoder: decoder, realType: Self.self)
	}

	func addSubTable(to: CRUDColumnNameDecoder, name: String, decoder: CRUDColumnNameDecoder) {
		to.addSubTable(SubTable(name: name, type: Self.self, decoder: decoder, realType: Self.self))
	}
}

public class CRUDColumnNameDecoder: Decoder {
	public var codingPath: [CodingKey] = []
	public var userInfo: [CodingUserInfoKey: Any] = [:]

	var tableNamePath: [String] = []
	public var collectedKeys: [(name: String, optional: Bool, type: Any.Type)] = []
	var subTables: [SubTableProto] = []
	var pendingReader: CRUDColumnNameUnkeyedReader?
	let depth: Int
	public init(depth d: Int = 0) {
		depth = d
	}
	func addSubTable<T: Codable>(_ name: String, type: T.Type, decoder: CRUDColumnNameDecoder) {
		guard subTables.filter({ $0.name == name }).count == 0 else {
			return
		}
		subTables.append(SubTable(name: name, type: type, decoder: decoder, realType: type))
	}
	func addSubTable<T: SubTableProto>(_ sub: T) {
		guard subTables.filter({ $0.name == sub.name }).count == 0 else {
			return
		}
		subTables.append(sub)
	}

	public func container<Key: CodingKey>(keyedBy type: Key.Type) throws -> KeyedDecodingContainer<Key> {
		return KeyedDecodingContainer<Key>(CRUDColumnNamesReader<Key>(self))
	}
	public func unkeyedContainer() throws -> UnkeyedDecodingContainer {
		let r = CRUDColumnNameUnkeyedReader(parent: self)
		if depth > 1 {
			r.count = 0
		}
		pendingReader = r
		return r
	}
	public func singleValueContainer() throws -> SingleValueDecodingContainer {
		let r = CRUDColumnNameUnkeyedReader(parent: self)
		return r
	}
}
