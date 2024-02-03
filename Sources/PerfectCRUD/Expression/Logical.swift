//
//  Logical.swift
//  PerfectCRUD
//
//  Created by Kyle Jessup on 2018-02-18.
//

import Foundation

// &&
public func && (lhs: CRUDBooleanExpression, rhs: CRUDBooleanExpression) -> CRUDBooleanExpression {
	return RealBooleanExpression(.and(lhs: lhs.crudExpression, rhs: rhs.crudExpression))
}
// ||
public func || (lhs: CRUDBooleanExpression, rhs: CRUDBooleanExpression) -> CRUDBooleanExpression {
	return RealBooleanExpression(.or(lhs: lhs.crudExpression, rhs: rhs.crudExpression))
}
// !
public prefix func ! (rhs: CRUDBooleanExpression) -> CRUDBooleanExpression {
	return RealBooleanExpression(.not(rhs: rhs.crudExpression))
}
