//
//  InInts.swift
//  PerfectCRUD
//
//  Created by Kyle Jessup on 2018-03-11.
//

import Foundation

// ~ IN
public func ~ <A: Codable>(lhs: KeyPath<A, Int>, rhs: [Int]) -> CRUDBooleanExpression {
	return RealBooleanExpression(.in(lhs: .keyPath(lhs), rhs: rhs.map { .integer($0) }))
}
public func ~ <A: Codable>(lhs: KeyPath<A, Int?>, rhs: [Int]) -> CRUDBooleanExpression {
	return RealBooleanExpression(.in(lhs: .keyPath(lhs), rhs: rhs.map { .integer($0) }))
}
public func ~ <A: Codable>(lhs: KeyPath<A, UInt>, rhs: [UInt]) -> CRUDBooleanExpression {
	return RealBooleanExpression(.in(lhs: .keyPath(lhs), rhs: rhs.map { .uinteger($0) }))
}
public func ~ <A: Codable>(lhs: KeyPath<A, UInt?>, rhs: [UInt]) -> CRUDBooleanExpression {
	return RealBooleanExpression(.in(lhs: .keyPath(lhs), rhs: rhs.map { .uinteger($0) }))
}
public func ~ <A: Codable>(lhs: KeyPath<A, Int64>, rhs: [Int64]) -> CRUDBooleanExpression {
	return RealBooleanExpression(.in(lhs: .keyPath(lhs), rhs: rhs.map { .integer64($0) }))
}
public func ~ <A: Codable>(lhs: KeyPath<A, Int64?>, rhs: [Int64]) -> CRUDBooleanExpression {
	return RealBooleanExpression(.in(lhs: .keyPath(lhs), rhs: rhs.map { .integer64($0) }))
}
public func ~ <A: Codable>(lhs: KeyPath<A, UInt64>, rhs: [UInt64]) -> CRUDBooleanExpression {
	return RealBooleanExpression(.in(lhs: .keyPath(lhs), rhs: rhs.map { .uinteger64($0) }))
}
public func ~ <A: Codable>(lhs: KeyPath<A, UInt64?>, rhs: [UInt64]) -> CRUDBooleanExpression {
	return RealBooleanExpression(.in(lhs: .keyPath(lhs), rhs: rhs.map { .uinteger64($0) }))
}
public func ~ <A: Codable>(lhs: KeyPath<A, Int32>, rhs: [Int32]) -> CRUDBooleanExpression {
	return RealBooleanExpression(.in(lhs: .keyPath(lhs), rhs: rhs.map { .integer32($0) }))
}
public func ~ <A: Codable>(lhs: KeyPath<A, Int32?>, rhs: [Int32]) -> CRUDBooleanExpression {
	return RealBooleanExpression(.in(lhs: .keyPath(lhs), rhs: rhs.map { .integer32($0) }))
}
public func ~ <A: Codable>(lhs: KeyPath<A, UInt32>, rhs: [UInt32]) -> CRUDBooleanExpression {
	return RealBooleanExpression(.in(lhs: .keyPath(lhs), rhs: rhs.map { .uinteger32($0) }))
}
public func ~ <A: Codable>(lhs: KeyPath<A, UInt32?>, rhs: [UInt32]) -> CRUDBooleanExpression {
	return RealBooleanExpression(.in(lhs: .keyPath(lhs), rhs: rhs.map { .uinteger32($0) }))
}
public func ~ <A: Codable>(lhs: KeyPath<A, Int16>, rhs: [Int16]) -> CRUDBooleanExpression {
	return RealBooleanExpression(.in(lhs: .keyPath(lhs), rhs: rhs.map { .integer16($0) }))
}
public func ~ <A: Codable>(lhs: KeyPath<A, Int16?>, rhs: [Int16]) -> CRUDBooleanExpression {
	return RealBooleanExpression(.in(lhs: .keyPath(lhs), rhs: rhs.map { .integer16($0) }))
}
public func ~ <A: Codable>(lhs: KeyPath<A, UInt16>, rhs: [UInt16]) -> CRUDBooleanExpression {
	return RealBooleanExpression(.in(lhs: .keyPath(lhs), rhs: rhs.map { .uinteger16($0) }))
}
public func ~ <A: Codable>(lhs: KeyPath<A, UInt16?>, rhs: [UInt16]) -> CRUDBooleanExpression {
	return RealBooleanExpression(.in(lhs: .keyPath(lhs), rhs: rhs.map { .uinteger16($0) }))
}
public func ~ <A: Codable>(lhs: KeyPath<A, Int8>, rhs: [Int8]) -> CRUDBooleanExpression {
	return RealBooleanExpression(.in(lhs: .keyPath(lhs), rhs: rhs.map { .integer8($0) }))
}
public func ~ <A: Codable>(lhs: KeyPath<A, Int8?>, rhs: [Int8]) -> CRUDBooleanExpression {
	return RealBooleanExpression(.in(lhs: .keyPath(lhs), rhs: rhs.map { .integer8($0) }))
}
public func ~ <A: Codable>(lhs: KeyPath<A, UInt8>, rhs: [UInt8]) -> CRUDBooleanExpression {
	return RealBooleanExpression(.in(lhs: .keyPath(lhs), rhs: rhs.map { .uinteger8($0) }))
}
public func ~ <A: Codable>(lhs: KeyPath<A, UInt8?>, rhs: [UInt8]) -> CRUDBooleanExpression {
	return RealBooleanExpression(.in(lhs: .keyPath(lhs), rhs: rhs.map { .uinteger8($0) }))
}
// !~ NOT IN
public func !~ <A: Codable>(lhs: KeyPath<A, Int>, rhs: [Int]) -> CRUDBooleanExpression {
	return !(lhs ~ rhs)
}
public func !~ <A: Codable>(lhs: KeyPath<A, Int?>, rhs: [Int]) -> CRUDBooleanExpression {
	return !(lhs ~ rhs)
}
public func !~ <A: Codable>(lhs: KeyPath<A, UInt>, rhs: [UInt]) -> CRUDBooleanExpression {
	return !(lhs ~ rhs)
}
public func !~ <A: Codable>(lhs: KeyPath<A, UInt?>, rhs: [UInt]) -> CRUDBooleanExpression {
	return !(lhs ~ rhs)
}
public func !~ <A: Codable>(lhs: KeyPath<A, Int64>, rhs: [Int64]) -> CRUDBooleanExpression {
	return !(lhs ~ rhs)
}
public func !~ <A: Codable>(lhs: KeyPath<A, Int64?>, rhs: [Int64]) -> CRUDBooleanExpression {
	return !(lhs ~ rhs)
}
public func !~ <A: Codable>(lhs: KeyPath<A, UInt64>, rhs: [UInt64]) -> CRUDBooleanExpression {
	return !(lhs ~ rhs)
}
public func !~ <A: Codable>(lhs: KeyPath<A, UInt64?>, rhs: [UInt64]) -> CRUDBooleanExpression {
	return !(lhs ~ rhs)
}
public func !~ <A: Codable>(lhs: KeyPath<A, Int32>, rhs: [Int32]) -> CRUDBooleanExpression {
	return !(lhs ~ rhs)
}
public func !~ <A: Codable>(lhs: KeyPath<A, Int32?>, rhs: [Int32]) -> CRUDBooleanExpression {
	return !(lhs ~ rhs)
}
public func !~ <A: Codable>(lhs: KeyPath<A, UInt32>, rhs: [UInt32]) -> CRUDBooleanExpression {
	return !(lhs ~ rhs)
}
public func !~ <A: Codable>(lhs: KeyPath<A, UInt32?>, rhs: [UInt32]) -> CRUDBooleanExpression {
	return !(lhs ~ rhs)
}
public func !~ <A: Codable>(lhs: KeyPath<A, Int16>, rhs: [Int16]) -> CRUDBooleanExpression {
	return !(lhs ~ rhs)
}
public func !~ <A: Codable>(lhs: KeyPath<A, Int16?>, rhs: [Int16]) -> CRUDBooleanExpression {
	return !(lhs ~ rhs)
}
public func !~ <A: Codable>(lhs: KeyPath<A, UInt16>, rhs: [UInt16]) -> CRUDBooleanExpression {
	return !(lhs ~ rhs)
}
public func !~ <A: Codable>(lhs: KeyPath<A, UInt16?>, rhs: [UInt16]) -> CRUDBooleanExpression {
	return !(lhs ~ rhs)
}
public func !~ <A: Codable>(lhs: KeyPath<A, Int8>, rhs: [Int8]) -> CRUDBooleanExpression {
	return !(lhs ~ rhs)
}
public func !~ <A: Codable>(lhs: KeyPath<A, Int8?>, rhs: [Int8]) -> CRUDBooleanExpression {
	return !(lhs ~ rhs)
}
public func !~ <A: Codable>(lhs: KeyPath<A, UInt8>, rhs: [UInt8]) -> CRUDBooleanExpression {
	return !(lhs ~ rhs)
}
public func !~ <A: Codable>(lhs: KeyPath<A, UInt8?>, rhs: [UInt8]) -> CRUDBooleanExpression {
	return !(lhs ~ rhs)
}
