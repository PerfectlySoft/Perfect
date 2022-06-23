//
//  In.swift
//  PerfectCRUD
//
//  Created by Kyle Jessup on 2018-02-18.
//

import Foundation

// ~ IN
public func ~ <A: Codable>(lhs: KeyPath<A, String>, rhs: [String]) -> CRUDBooleanExpression {
	return RealBooleanExpression(.in(lhs: .keyPath(lhs), rhs: rhs.map { .string($0) }))
}
public func ~ <A: Codable>(lhs: KeyPath<A, Double>, rhs: [Double]) -> CRUDBooleanExpression {
	return RealBooleanExpression(.in(lhs: .keyPath(lhs), rhs: rhs.map { .decimal($0) }))
}
public func ~ <A: Codable>(lhs: KeyPath<A, UUID>, rhs: [UUID]) -> CRUDBooleanExpression {
	return RealBooleanExpression(.in(lhs: .keyPath(lhs), rhs: rhs.map { .uuid($0) }))
}
public func ~ <A: Codable>(lhs: KeyPath<A, Date>, rhs: [Date]) -> CRUDBooleanExpression {
	return RealBooleanExpression(.in(lhs: .keyPath(lhs), rhs: rhs.map { .date($0) }))
}
public func ~ <A: Codable>(lhs: KeyPath<A, String?>, rhs: [String]) -> CRUDBooleanExpression {
	return RealBooleanExpression(.in(lhs: .keyPath(lhs), rhs: rhs.map { .string($0) }))
}
public func ~ <A: Codable>(lhs: KeyPath<A, Double?>, rhs: [Double]) -> CRUDBooleanExpression {
	return RealBooleanExpression(.in(lhs: .keyPath(lhs), rhs: rhs.map { .decimal($0) }))
}
public func ~ <A: Codable>(lhs: KeyPath<A, UUID?>, rhs: [UUID]) -> CRUDBooleanExpression {
	return RealBooleanExpression(.in(lhs: .keyPath(lhs), rhs: rhs.map { .uuid($0) }))
}
public func ~ <A: Codable>(lhs: KeyPath<A, Date?>, rhs: [Date]) -> CRUDBooleanExpression {
	return RealBooleanExpression(.in(lhs: .keyPath(lhs), rhs: rhs.map { .date($0) }))
}
// !~ NOT IN
public func !~ <A: Codable>(lhs: KeyPath<A, String>, rhs: [String]) -> CRUDBooleanExpression {
	return !(lhs ~ rhs)
}
public func !~ <A: Codable>(lhs: KeyPath<A, Double>, rhs: [Double]) -> CRUDBooleanExpression {
	return !(lhs ~ rhs)
}
public func !~ <A: Codable>(lhs: KeyPath<A, UUID>, rhs: [UUID]) -> CRUDBooleanExpression {
	return !(lhs ~ rhs)
}
public func !~ <A: Codable>(lhs: KeyPath<A, Date>, rhs: [Date]) -> CRUDBooleanExpression {
	return !(lhs ~ rhs)
}
