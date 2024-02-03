//
//  PerfectCRUDCodingKeyPaths.swift
//  PerfectCRUD
//
//  Created by Kyle Jessup on 2017-11-27.
//

import Foundation

class CRUDKeyPathsReader<K: CodingKey>: KeyedDecodingContainerProtocol {
	typealias Key = K
	let codingPath: [CodingKey] = []
	let allKeys: [Key] = []
	let parent: CRUDKeyPathsDecoder

	init(_ p: CRUDKeyPathsDecoder) {
		parent = p
	}
	func contains(_ key: Key) -> Bool {
		return true
	}
	func decodeNil(forKey key: Key) throws -> Bool {
		return false
	}
	func decode(_ type: Bool.Type, forKey key: Key) throws -> Bool {
		return try parent.countBool(key)
	}
	func decode(_ type: Int.Type, forKey key: Key) throws -> Int {
		return Int(parent.countKey(key))
	}
	func decode(_ type: Int8.Type, forKey key: Key) throws -> Int8 {
		return parent.countKey(key)
	}
	func decode(_ type: Int16.Type, forKey key: Key) throws -> Int16 {
		return Int16(parent.countKey(key))
	}
	func decode(_ type: Int32.Type, forKey key: Key) throws -> Int32 {
		return Int32(parent.countKey(key))
	}
	func decode(_ type: Int64.Type, forKey key: Key) throws -> Int64 {
		return Int64(parent.countKey(key))
	}
	func decode(_ type: UInt.Type, forKey key: Key) throws -> UInt {
		return UInt(parent.countKey(key))
	}
	func decode(_ type: UInt8.Type, forKey key: Key) throws -> UInt8 {
		return UInt8(parent.countKey(key))
	}
	func decode(_ type: UInt16.Type, forKey key: Key) throws -> UInt16 {
		return UInt16(parent.countKey(key))
	}
	func decode(_ type: UInt32.Type, forKey key: Key) throws -> UInt32 {
		return UInt32(parent.countKey(key))
	}
	func decode(_ type: UInt64.Type, forKey key: Key) throws -> UInt64 {
		return UInt64(parent.countKey(key))
	}
	func decode(_ type: Float.Type, forKey key: Key) throws -> Float {
		return Float(parent.countKey(key))
	}
	func decode(_ type: Double.Type, forKey key: Key) throws -> Double {
		return Double(parent.countKey(key))
	}
	func decode(_ type: String.Type, forKey key: Key) throws -> String {
		return "\(parent.countKey(key))"
	}
	// swiftlint:disable comma force_cast
	func decode<T: Decodable>(_ type: T.Type, forKey key: Key) throws -> T {
		if type is WrappedCodableProvider.Type {
			parent.wrappedKey = key
			let decoded = try T(from: parent)
			defer {
				parent.wrappedKey = nil
			}
			return decoded
		}
		let counter = parent.countKey(key)
		if let special = SpecialType(type) {
			switch special {
			case .uint8Array:
				return [UInt8(counter)] as! T
			case .int8Array:
				return [Int8(counter)] as! T
			case .data:
				return Data([UInt8(counter)]) as! T
			case .uuid:
				return UUID(uuid: uuid_t(UInt8(counter),0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)) as! T
			case .date:
				return Date(timeIntervalSinceReferenceDate: TimeInterval(counter)) as! T
			case .url:
				return URL(string: "http://localhost:\(counter)/")! as! T
			case .codable:
				let decoder = CRUDKeyPathsDecoder(depth: 1 + parent.depth)
				let decoded = try T(from: decoder)
				parent.subTypeMap.append((key.stringValue, type, decoder))
				return decoded
			case .wrapped:
				throw CRUDDecoderError("Unhandled decode type \(type)")
			}
		} else {
			let decoder = CRUDKeyPathsDecoder(depth: 1 + parent.depth)
			let decoded = try T(from: decoder)
			parent.subTypeMap.append((key.stringValue, type, decoder))
			return decoded
		}
	}
	func nestedContainer<NestedKey>(keyedBy type: NestedKey.Type, forKey key: Key) throws -> KeyedDecodingContainer<NestedKey> where NestedKey: CodingKey {
		throw CRUDDecoderError("Unimplimented nestedContainer")
	}
	func nestedUnkeyedContainer(forKey key: Key) throws -> UnkeyedDecodingContainer {
		throw CRUDDecoderError("Unimplimented nestedUnkeyedContainer")
	}
	func superDecoder() throws -> Decoder {
		return parent
	}
	func superDecoder(forKey key: Key) throws -> Decoder {
		throw CRUDDecoderError("Unimplimented superDecoder")
	}
}

class CRUDKeyPathsUnkeyedReader: UnkeyedDecodingContainer, SingleValueDecodingContainer {
	let codingPath: [CodingKey] = []
	var count: Int? = 1
	var isAtEnd: Bool { return !(currentIndex < count ?? 0) }
	var currentIndex: Int = 0
	let parent: CRUDKeyPathsDecoder
	let wrappedKey: CodingKey

	init(_ p: CRUDKeyPathsDecoder, key: CodingKey) {
		wrappedKey = key
		parent = p
	}

	func decodeNil() -> Bool {
		return false
	}

	func decode(_ type: Bool.Type) throws -> Bool {
		return try parent.countBool(wrappedKey)
	}

	func decode(_ type: Int.Type) throws -> Int {
		return Int(parent.countKey(wrappedKey))
	}

	func decode(_ type: Int8.Type) throws -> Int8 {
		return Int8(parent.countKey(wrappedKey))
	}

	func decode(_ type: Int16.Type) throws -> Int16 {
		return Int16(parent.countKey(wrappedKey))
	}

	func decode(_ type: Int32.Type) throws -> Int32 {
		return Int32(parent.countKey(wrappedKey))
	}

	func decode(_ type: Int64.Type) throws -> Int64 {
		return Int64(parent.countKey(wrappedKey))
	}

	func decode(_ type: UInt.Type) throws -> UInt {
		return UInt(parent.countKey(wrappedKey))
	}

	func decode(_ type: UInt8.Type) throws -> UInt8 {
		return UInt8(parent.countKey(wrappedKey))
	}

	func decode(_ type: UInt16.Type) throws -> UInt16 {
		return UInt16(parent.countKey(wrappedKey))
	}

	func decode(_ type: UInt32.Type) throws -> UInt32 {
		return UInt32(parent.countKey(wrappedKey))
	}

	func decode(_ type: UInt64.Type) throws -> UInt64 {
		return UInt64(parent.countKey(wrappedKey))
	}

	func decode(_ type: Float.Type) throws -> Float {
		return Float(parent.countKey(wrappedKey))
	}

	func decode(_ type: Double.Type) throws -> Double {
		return Double(parent.countKey(wrappedKey))
	}

	func decode(_ type: String.Type) throws -> String {
		return "\(parent.countKey(wrappedKey))"
	}

	// swiftlint:disable comma
	func decode<T: Decodable>(_ type: T.Type) throws -> T {
		// this is being called in some cases for primitive types like Int
		// 	instead of the proper funtion above
		switch type {
		case let t as Bool.Type: return try decode(t) as! T
		case let t as Int.Type: return try decode(t) as! T
		case let t as Int8.Type: return try decode(t) as! T
		case let t as Int16.Type: return try decode(t) as! T
		case let t as Int32.Type: return try decode(t) as! T
		case let t as Int64.Type: return try decode(t) as! T
		case let t as UInt.Type: return try decode(t) as! T
		case let t as UInt8.Type: return try decode(t) as! T
		case let t as UInt16.Type: return try decode(t) as! T
		case let t as UInt32.Type: return try decode(t) as! T
		case let t as UInt64.Type: return try decode(t) as! T
		case let t as Float.Type: return try decode(t) as! T
		case let t as Double.Type: return try decode(t) as! T
		case let t as String.Type: return try decode(t) as! T
		default: ()
		}
		currentIndex += 1
		let counter = parent.countKey(wrappedKey)
		if let special = SpecialType(type) {
			switch special {
			case .uint8Array:
				return [UInt8(counter)] as! T
			case .int8Array:
				return [Int8(counter)] as! T
			case .data:
				return Data([UInt8(counter)]) as! T
			case .uuid:
				return UUID(uuid: uuid_t(UInt8(counter),0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)) as! T
			case .date:
				return Date(timeIntervalSinceReferenceDate: TimeInterval(counter)) as! T
			case .url:
				return URL(string: "http://localhost:\(counter)/")! as! T
			case .codable:
				let decoder = CRUDKeyPathsDecoder(depth: 1 + parent.depth)
				let decoded = try T(from: decoder)
				parent.subTypeMap.append((wrappedKey.stringValue, type, decoder))
				return decoded
			case .wrapped:
				throw CRUDDecoderError("Unhandled decode type \(type)")
			}
		} else {
			let decoder = CRUDKeyPathsDecoder(depth: 1 + parent.depth)
			let decoded = try T(from: decoder)
			parent.subTypeMap.append((wrappedKey.stringValue, type, decoder))
			return decoded
		}
	}

	func nestedContainer<NestedKey>(keyedBy type: NestedKey.Type) throws -> KeyedDecodingContainer<NestedKey> where NestedKey: CodingKey {
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

class MyUnkeyedDecodingContainer: UnkeyedDecodingContainer {
	var codingPath: [CodingKey] = []
	var count: Int? = 0
	var isAtEnd: Bool = true
	var currentIndex: Int = 0

	func decodeNil() throws -> Bool {
		throw CRUDDecoderError("MyUnkeyedDecodingContainer zero count")
	}

	func decode(_ type: Bool.Type) throws -> Bool {
		throw CRUDDecoderError("MyUnkeyedDecodingContainer zero count")
	}

	func decode(_ type: String.Type) throws -> String {
		throw CRUDDecoderError("MyUnkeyedDecodingContainer zero count")
	}

	func decode(_ type: Double.Type) throws -> Double {
		throw CRUDDecoderError("MyUnkeyedDecodingContainer zero count")
	}

	func decode(_ type: Float.Type) throws -> Float {
		throw CRUDDecoderError("MyUnkeyedDecodingContainer zero count")
	}

	func decode(_ type: Int.Type) throws -> Int {
		throw CRUDDecoderError("MyUnkeyedDecodingContainer zero count")
	}

	func decode(_ type: Int8.Type) throws -> Int8 {
		throw CRUDDecoderError("MyUnkeyedDecodingContainer zero count")
	}

	func decode(_ type: Int16.Type) throws -> Int16 {
		throw CRUDDecoderError("MyUnkeyedDecodingContainer zero count")
	}

	func decode(_ type: Int32.Type) throws -> Int32 {
		throw CRUDDecoderError("MyUnkeyedDecodingContainer zero count")
	}

	func decode(_ type: Int64.Type) throws -> Int64 {
		throw CRUDDecoderError("MyUnkeyedDecodingContainer zero count")
	}

	func decode(_ type: UInt.Type) throws -> UInt {
		throw CRUDDecoderError("MyUnkeyedDecodingContainer zero count")
	}

	func decode(_ type: UInt8.Type) throws -> UInt8 {
		throw CRUDDecoderError("MyUnkeyedDecodingContainer zero count")
	}

	func decode(_ type: UInt16.Type) throws -> UInt16 {
		throw CRUDDecoderError("MyUnkeyedDecodingContainer zero count")
	}

	func decode(_ type: UInt32.Type) throws -> UInt32 {
		throw CRUDDecoderError("MyUnkeyedDecodingContainer zero count")
	}

	func decode(_ type: UInt64.Type) throws -> UInt64 {
		throw CRUDDecoderError("MyUnkeyedDecodingContainer zero count")
	}

	func decode<T>(_ type: T.Type) throws -> T where T: Decodable {
		throw CRUDDecoderError("MyUnkeyedDecodingContainer zero count")
	}

	func nestedContainer<NestedKey>(keyedBy type: NestedKey.Type) throws -> KeyedDecodingContainer<NestedKey> where NestedKey: CodingKey {
		throw CRUDDecoderError("MyUnkeyedDecodingContainer zero count")
	}

	func nestedUnkeyedContainer() throws -> UnkeyedDecodingContainer {
		throw CRUDDecoderError("MyUnkeyedDecodingContainer zero count")
	}

	func superDecoder() throws -> Decoder {
		throw CRUDDecoderError("MyUnkeyedDecodingContainer zero count")
	}
}

public class CRUDKeyPathsDecoder: Decoder {
	public var codingPath: [CodingKey] = []
	public var userInfo: [CodingUserInfoKey: Any] = [:]
	var counter: Int8 = 1
	var boolCounter: Int8 = 0
	var typeMap: [Int8: String] = [:]
	var subTypeMap: [(String, Decodable.Type, CRUDKeyPathsDecoder)] = []
	let depth: Int
	var wrappedKey: CodingKey?

	init(depth d: Int = 0) {
		depth = d
	}

	func countKey(_ key: CodingKey) -> Int8 {
		counter += 1
		typeMap[counter] = key.stringValue
		return counter
	}

	func countBool(_ key: CodingKey) throws -> Bool {
		guard boolCounter < 2 else {
			throw CRUDDecoderError("Perfect-CRUD table types can have up to two Bool properties. Try using small ints (Int8) with bool 'var' accessors.")
		}
		typeMap[boolCounter] = key.stringValue
		boolCounter += 1
		return boolCounter == 2
	}

	public func container<Key: CodingKey>(keyedBy type: Key.Type) throws -> KeyedDecodingContainer<Key> {
		return KeyedDecodingContainer<Key>(CRUDKeyPathsReader<Key>(self))
	}
	public func unkeyedContainer() throws -> UnkeyedDecodingContainer {
		return MyUnkeyedDecodingContainer()
	}
	public func singleValueContainer() throws -> SingleValueDecodingContainer {
		guard let wrappedKey = self.wrappedKey else {
			throw CRUDDecoderError("No wrappedKey waiting for unkeyedContainer")
		}
		return CRUDKeyPathsUnkeyedReader(self, key: wrappedKey)
	}
	public func getKeyPathName(_ instance: Any, keyPath: AnyKeyPath) throws -> String? {
		guard let v = instance[keyPath: keyPath] else {
			return nil
		}
		return try getKeyPathName(fromValue: v)
	}
	private func getKeyPathName(fromValue v: Any) throws -> String? {
		switch v {
		case let b as Bool:
			return typeMap[b ? 1 : 0]
		case let s as String:
			guard let v = Int8(s) else {
				return nil
			}
			return typeMap[v]
		case let i as Int:
			return typeMap[Int8(i)]
		case let i as Int8:
			return typeMap[Int8(i)]
		case let i as Int16:
			return typeMap[Int8(i)]
		case let i as Int32:
			return typeMap[Int8(i)]
		case let i as Int64:
			return typeMap[Int8(i)]
		case let i as UInt:
			return typeMap[Int8(i)]
		case let i as UInt8:
			return typeMap[Int8(i)]
		case let i as UInt16:
			return typeMap[Int8(i)]
		case let i as UInt32:
			return typeMap[Int8(i)]
		case let i as UInt64:
			return typeMap[Int8(i)]
		case let i as Float:
			return typeMap[Int8(i)]
		case let i as Double:
			return typeMap[Int8(i)]
		case let o as Any?:
			guard let unType = o else {
				return nil
			}
			if let found = subTypeMap.first(where: { $0.1 == type(of: unType) }) {
				return found.0
			}
			if let special = SpecialType(type(of: unType)) {
				switch special {
				case .uint8Array:
					return typeMap[Int8((v as! [UInt8])[0])]
				case .int8Array:
					return typeMap[Int8((v as! [Int8])[0])]
				case .data:
					return typeMap[Int8((v as! Data).first!)]
				case .uuid:
					return typeMap[Int8((v as! UUID).uuid.0)]
				case .date:
					return typeMap[Int8((v as! Date).timeIntervalSinceReferenceDate)]
				case .url:
					return typeMap[Int8((v as! URL).port!)]
				case .codable, .wrapped:
					throw CRUDDecoderError("Unsupported operation on codable column.")
				}
			}
			return nil
		default:
			guard let found = subTypeMap.first(where: { $0.1 == type(of: v) }) else {
				return nil
			}
			return found.0
		}
	}
}
