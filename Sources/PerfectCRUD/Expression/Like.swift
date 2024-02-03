//
//  Like.swift
//  PerfectCRUD
//
//  Created by Kyle Jessup on 2018-02-18.
//

import Foundation

// %=% LIKE
public func %=% <A: Codable>(lhs: KeyPath<A, String>, rhs: String) -> CRUDBooleanExpression {
	return RealBooleanExpression(.like(lhs: .keyPath(lhs), wild1: true, rhs, wild2: true))
}
public func %=% <A: Codable>(lhs: KeyPath<A, String?>, rhs: String) -> CRUDBooleanExpression {
	return RealBooleanExpression(.like(lhs: .keyPath(lhs), wild1: true, rhs, wild2: true))
}
// *~ LIKE v%
public func =% <A: Codable>(lhs: KeyPath<A, String>, rhs: String) -> CRUDBooleanExpression {
	return RealBooleanExpression(.like(lhs: .keyPath(lhs), wild1: false, rhs, wild2: true))
}
public func =% <A: Codable>(lhs: KeyPath<A, String?>, rhs: String) -> CRUDBooleanExpression {
	return RealBooleanExpression(.like(lhs: .keyPath(lhs), wild1: false, rhs, wild2: true))
}
// ~* LIKE %v
public func %= <A: Codable>(lhs: KeyPath<A, String>, rhs: String) -> CRUDBooleanExpression {
	return RealBooleanExpression(.like(lhs: .keyPath(lhs), wild1: true, rhs, wild2: false))
}
public func %= <A: Codable>(lhs: KeyPath<A, String?>, rhs: String) -> CRUDBooleanExpression {
	return RealBooleanExpression(.like(lhs: .keyPath(lhs), wild1: true, rhs, wild2: false))
}
// !~ NOT LIKE
public func %!=% <A: Codable>(lhs: KeyPath<A, String>, rhs: String) -> CRUDBooleanExpression {
	return !(lhs %=% rhs)
}
public func %!=% <A: Codable>(lhs: KeyPath<A, String?>, rhs: String) -> CRUDBooleanExpression {
	return !(lhs %=% rhs)
}
public func !=% <A: Codable>(lhs: KeyPath<A, String>, rhs: String) -> CRUDBooleanExpression {
	return !(lhs =% rhs)
}
public func !=% <A: Codable>(lhs: KeyPath<A, String?>, rhs: String) -> CRUDBooleanExpression {
	return !(lhs =% rhs)
}
public func %!= <A: Codable>(lhs: KeyPath<A, String>, rhs: String) -> CRUDBooleanExpression {
	return !(lhs %= rhs)
}
public func %!= <A: Codable>(lhs: KeyPath<A, String?>, rhs: String) -> CRUDBooleanExpression {
	return !(lhs %= rhs)
}
