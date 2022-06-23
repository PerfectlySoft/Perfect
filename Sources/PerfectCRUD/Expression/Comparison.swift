//
//  Comparison.swift
//  PerfectCRUD
//
//  Created by Kyle Jessup on 2018-02-18.
//

import Foundation

// <
public func < <A: Codable>(lhs: KeyPath<A, String>, rhs: String) -> CRUDBooleanExpression {
	return RealBooleanExpression(.lessThan(lhs: .keyPath(lhs), rhs: .string(rhs)))
}
public func < <A: Codable>(lhs: KeyPath<A, Double>, rhs: Double) -> CRUDBooleanExpression {
	return RealBooleanExpression(.lessThan(lhs: .keyPath(lhs), rhs: .decimal(rhs)))
}
public func < <A: Codable>(lhs: KeyPath<A, Bool>, rhs: Bool) -> CRUDBooleanExpression {
	return RealBooleanExpression(.lessThan(lhs: .keyPath(lhs), rhs: .bool(rhs)))
}
public func < <A: Codable>(lhs: KeyPath<A, UUID>, rhs: UUID) -> CRUDBooleanExpression {
	return RealBooleanExpression(.lessThan(lhs: .keyPath(lhs), rhs: .uuid(rhs)))
}
public func < <A: Codable>(lhs: KeyPath<A, Date>, rhs: Date) -> CRUDBooleanExpression {
	return RealBooleanExpression(.lessThan(lhs: .keyPath(lhs), rhs: .date(rhs)))
}
// >
public func > <A: Codable>(lhs: KeyPath<A, String>, rhs: String) -> CRUDBooleanExpression {
	return RealBooleanExpression(.greaterThan(lhs: .keyPath(lhs), rhs: .string(rhs)))
}
public func > <A: Codable>(lhs: KeyPath<A, Double>, rhs: Double) -> CRUDBooleanExpression {
	return RealBooleanExpression(.greaterThan(lhs: .keyPath(lhs), rhs: .decimal(rhs)))
}
public func > <A: Codable>(lhs: KeyPath<A, Bool>, rhs: Bool) -> CRUDBooleanExpression {
	return RealBooleanExpression(.greaterThan(lhs: .keyPath(lhs), rhs: .bool(rhs)))
}
public func > <A: Codable>(lhs: KeyPath<A, UUID>, rhs: UUID) -> CRUDBooleanExpression {
	return RealBooleanExpression(.greaterThan(lhs: .keyPath(lhs), rhs: .uuid(rhs)))
}
public func > <A: Codable>(lhs: KeyPath<A, Date>, rhs: Date) -> CRUDBooleanExpression {
	return RealBooleanExpression(.greaterThan(lhs: .keyPath(lhs), rhs: .date(rhs)))
}
// <=
public func <= <A: Codable>(lhs: KeyPath<A, String>, rhs: String) -> CRUDBooleanExpression {
	return RealBooleanExpression(.lessThanEqual(lhs: .keyPath(lhs), rhs: .string(rhs)))
}
public func <= <A: Codable>(lhs: KeyPath<A, Double>, rhs: Double) -> CRUDBooleanExpression {
	return RealBooleanExpression(.lessThanEqual(lhs: .keyPath(lhs), rhs: .decimal(rhs)))
}
public func <= <A: Codable>(lhs: KeyPath<A, Bool>, rhs: Bool) -> CRUDBooleanExpression {
	return RealBooleanExpression(.lessThanEqual(lhs: .keyPath(lhs), rhs: .bool(rhs)))
}
public func <= <A: Codable>(lhs: KeyPath<A, UUID>, rhs: UUID) -> CRUDBooleanExpression {
	return RealBooleanExpression(.lessThanEqual(lhs: .keyPath(lhs), rhs: .uuid(rhs)))
}
public func <= <A: Codable>(lhs: KeyPath<A, Date>, rhs: Date) -> CRUDBooleanExpression {
	return RealBooleanExpression(.lessThanEqual(lhs: .keyPath(lhs), rhs: .date(rhs)))
}
// >=
public func >= <A: Codable>(lhs: KeyPath<A, String>, rhs: String) -> CRUDBooleanExpression {
	return RealBooleanExpression(.greaterThanEqual(lhs: .keyPath(lhs), rhs: .string(rhs)))
}
public func >= <A: Codable>(lhs: KeyPath<A, Double>, rhs: Double) -> CRUDBooleanExpression {
	return RealBooleanExpression(.greaterThanEqual(lhs: .keyPath(lhs), rhs: .decimal(rhs)))
}
public func >= <A: Codable>(lhs: KeyPath<A, Bool>, rhs: Bool) -> CRUDBooleanExpression {
	return RealBooleanExpression(.greaterThanEqual(lhs: .keyPath(lhs), rhs: .bool(rhs)))
}
public func >= <A: Codable>(lhs: KeyPath<A, UUID>, rhs: UUID) -> CRUDBooleanExpression {
	return RealBooleanExpression(.greaterThanEqual(lhs: .keyPath(lhs), rhs: .uuid(rhs)))
}
public func >= <A: Codable>(lhs: KeyPath<A, Date>, rhs: Date) -> CRUDBooleanExpression {
	return RealBooleanExpression(.greaterThanEqual(lhs: .keyPath(lhs), rhs: .date(rhs)))
}
