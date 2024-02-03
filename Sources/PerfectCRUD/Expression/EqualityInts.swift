//
//  EqualityInts.swift
//  PerfectCRUD
//
//  Created by Kyle Jessup on 2018-03-11.
//

import Foundation

// ==
public func == <A: Codable>(lhs: KeyPath<A, Int>, rhs: Int) -> CRUDBooleanExpression {
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .integer(rhs)))
}
public func == <A: Codable>(lhs: KeyPath<A, UInt>, rhs: UInt) -> CRUDBooleanExpression {
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .uinteger(rhs)))
}
public func == <A: Codable>(lhs: KeyPath<A, UInt>, rhs: Int) -> CRUDBooleanExpression {
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .uinteger(UInt(rhs))))
}
public func == <A: Codable>(lhs: KeyPath<A, Int64>, rhs: Int64) -> CRUDBooleanExpression {
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .integer64(rhs)))
}
public func == <A: Codable>(lhs: KeyPath<A, Int64>, rhs: Int) -> CRUDBooleanExpression {
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .integer64(Int64(rhs))))
}
public func == <A: Codable>(lhs: KeyPath<A, UInt64>, rhs: UInt64) -> CRUDBooleanExpression {
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .uinteger64(rhs)))
}
public func == <A: Codable>(lhs: KeyPath<A, UInt64>, rhs: Int) -> CRUDBooleanExpression {
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .uinteger64(UInt64(rhs))))
}
public func == <A: Codable>(lhs: KeyPath<A, Int32>, rhs: Int32) -> CRUDBooleanExpression {
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .integer32(rhs)))
}
public func == <A: Codable>(lhs: KeyPath<A, Int32>, rhs: Int) -> CRUDBooleanExpression {
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .integer32(Int32(rhs))))
}
public func == <A: Codable>(lhs: KeyPath<A, UInt32>, rhs: UInt32) -> CRUDBooleanExpression {
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .uinteger32(rhs)))
}
public func == <A: Codable>(lhs: KeyPath<A, UInt32>, rhs: Int) -> CRUDBooleanExpression {
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .uinteger32(UInt32(rhs))))
}
public func == <A: Codable>(lhs: KeyPath<A, Int16>, rhs: Int16) -> CRUDBooleanExpression {
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .integer16(rhs)))
}
public func == <A: Codable>(lhs: KeyPath<A, Int16>, rhs: Int) -> CRUDBooleanExpression {
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .integer16(Int16(rhs))))
}
public func == <A: Codable>(lhs: KeyPath<A, UInt16>, rhs: UInt16) -> CRUDBooleanExpression {
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .uinteger16(rhs)))
}
public func == <A: Codable>(lhs: KeyPath<A, UInt16>, rhs: Int) -> CRUDBooleanExpression {
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .uinteger16(UInt16(rhs))))
}
public func == <A: Codable>(lhs: KeyPath<A, Int8>, rhs: Int8) -> CRUDBooleanExpression {
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .integer8(rhs)))
}
public func == <A: Codable>(lhs: KeyPath<A, Int8>, rhs: Int) -> CRUDBooleanExpression {
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .integer8(Int8(rhs))))
}
public func == <A: Codable>(lhs: KeyPath<A, UInt8>, rhs: UInt8) -> CRUDBooleanExpression {
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .uinteger8(rhs)))
}
public func == <A: Codable>(lhs: KeyPath<A, UInt8>, rhs: Int) -> CRUDBooleanExpression {
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .uinteger8(UInt8(rhs))))
}
public func == <A: Codable>(lhs: KeyPath<A, [UInt8]>, rhs: [UInt8]) -> CRUDBooleanExpression {
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .blob(rhs)))
}
public func == <A: Codable>(lhs: KeyPath<A, [Int8]>, rhs: [Int8]) -> CRUDBooleanExpression {
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .sblob(rhs)))
}
// == ?
public func == <A: Codable>(lhs: KeyPath<A, Int?>, rhs: Int?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .integer(rhs)))
	}
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .null))
}
public func == <A: Codable>(lhs: KeyPath<A, UInt?>, rhs: UInt?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .uinteger(rhs)))
	}
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .null))
}
public func == <A: Codable>(lhs: KeyPath<A, UInt?>, rhs: Int?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .uinteger(UInt(rhs))))
	}
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .null))
}
public func == <A: Codable>(lhs: KeyPath<A, Int64?>, rhs: Int64?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .integer64(rhs)))
	}
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .null))
}
public func == <A: Codable>(lhs: KeyPath<A, Int64?>, rhs: Int?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .integer64(Int64(rhs))))
	}
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .null))
}
public func == <A: Codable>(lhs: KeyPath<A, UInt64?>, rhs: UInt64?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .uinteger64(rhs)))
	}
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .null))
}
public func == <A: Codable>(lhs: KeyPath<A, UInt64?>, rhs: Int?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .uinteger64(UInt64(rhs))))
	}
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .null))
}
public func == <A: Codable>(lhs: KeyPath<A, Int32?>, rhs: Int32?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .integer32(rhs)))
	}
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .null))
}
public func == <A: Codable>(lhs: KeyPath<A, Int32?>, rhs: Int?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .integer32(Int32(rhs))))
	}
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .null))
}
public func == <A: Codable>(lhs: KeyPath<A, UInt32?>, rhs: UInt32?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .uinteger32(rhs)))
	}
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .null))
}
public func == <A: Codable>(lhs: KeyPath<A, UInt32?>, rhs: Int?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .uinteger32(UInt32(rhs))))
	}
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .null))
}
public func == <A: Codable>(lhs: KeyPath<A, Int16?>, rhs: Int16?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .integer16(rhs)))
	}
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .null))
}
public func == <A: Codable>(lhs: KeyPath<A, Int16?>, rhs: Int?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .integer16(Int16(rhs))))
	}
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .null))
}
public func == <A: Codable>(lhs: KeyPath<A, UInt16?>, rhs: UInt16?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .uinteger16(rhs)))
	}
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .null))
}
public func == <A: Codable>(lhs: KeyPath<A, UInt16?>, rhs: Int?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .uinteger16(UInt16(rhs))))
	}
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .null))
}
public func == <A: Codable>(lhs: KeyPath<A, Int8?>, rhs: Int8?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .integer8(rhs)))
	}
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .null))
}
public func == <A: Codable>(lhs: KeyPath<A, Int8?>, rhs: Int?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .integer8(Int8(rhs))))
	}
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .null))
}
public func == <A: Codable>(lhs: KeyPath<A, UInt8?>, rhs: UInt8?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .uinteger8(rhs)))
	}
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .null))
}
public func == <A: Codable>(lhs: KeyPath<A, UInt8?>, rhs: Int?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .uinteger8(UInt8(rhs))))
	}
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .null))
}
public func == <A: Codable>(lhs: KeyPath<A, [UInt8]?>, rhs: [UInt8]?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .blob(rhs)))
	}
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .null))
}
public func == <A: Codable>(lhs: KeyPath<A, [Int8]?>, rhs: [Int8]?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .sblob(rhs)))
	}
	return RealBooleanExpression(.equality(lhs: .keyPath(lhs), rhs: .null))
}
// !=
public func != <A: Codable>(lhs: KeyPath<A, Int>, rhs: Int) -> CRUDBooleanExpression {
	return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .integer(rhs)))
}
public func != <A: Codable>(lhs: KeyPath<A, UInt>, rhs: UInt) -> CRUDBooleanExpression {
	return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .uinteger(rhs)))
}
public func != <A: Codable>(lhs: KeyPath<A, UInt>, rhs: Int) -> CRUDBooleanExpression {
	return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .uinteger(UInt(rhs))))
}
public func != <A: Codable>(lhs: KeyPath<A, Int64>, rhs: Int64) -> CRUDBooleanExpression {
	return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .integer64(rhs)))
}
public func != <A: Codable>(lhs: KeyPath<A, Int64>, rhs: Int) -> CRUDBooleanExpression {
	return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .integer64(Int64(rhs))))
}
public func != <A: Codable>(lhs: KeyPath<A, Int32>, rhs: Int32) -> CRUDBooleanExpression {
	return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .integer32(rhs)))
}
public func != <A: Codable>(lhs: KeyPath<A, Int32>, rhs: Int) -> CRUDBooleanExpression {
	return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .integer32(Int32(rhs))))
}
public func != <A: Codable>(lhs: KeyPath<A, Int16>, rhs: Int16) -> CRUDBooleanExpression {
	return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .integer16(rhs)))
}
public func != <A: Codable>(lhs: KeyPath<A, Int16>, rhs: Int) -> CRUDBooleanExpression {
	return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .integer16(Int16(rhs))))
}
public func != <A: Codable>(lhs: KeyPath<A, Int8>, rhs: Int8) -> CRUDBooleanExpression {
	return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .integer8(rhs)))
}
public func != <A: Codable>(lhs: KeyPath<A, Int8>, rhs: Int) -> CRUDBooleanExpression {
	return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .integer8(Int8(rhs))))
}
public func != <A: Codable>(lhs: KeyPath<A, [UInt8]>, rhs: [UInt8]) -> CRUDBooleanExpression {
	return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .blob(rhs)))
}
public func != <A: Codable>(lhs: KeyPath<A, [Int8]>, rhs: [Int8]) -> CRUDBooleanExpression {
	return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .sblob(rhs)))
}
// != ?
public func != <A: Codable>(lhs: KeyPath<A, Int?>, rhs: Int?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .integer(rhs)))
	}
	return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .null))
}
public func != <A: Codable>(lhs: KeyPath<A, UInt?>, rhs: UInt?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .uinteger(rhs)))
	}
	return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .null))
}
public func != <A: Codable>(lhs: KeyPath<A, UInt?>, rhs: Int?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .uinteger(UInt(rhs))))
	}
	return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .null))
}
public func != <A: Codable>(lhs: KeyPath<A, Int64?>, rhs: Int64?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .integer64(rhs)))
	}
	return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .null))
}
public func != <A: Codable>(lhs: KeyPath<A, Int64?>, rhs: Int?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .integer64(Int64(rhs))))
	}
	return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .null))
}
public func != <A: Codable>(lhs: KeyPath<A, UInt64?>, rhs: UInt64?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .uinteger64(rhs)))
	}
	return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .null))
}
public func != <A: Codable>(lhs: KeyPath<A, UInt64?>, rhs: Int?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .uinteger64(UInt64(rhs))))
	}
	return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .null))
}
public func != <A: Codable>(lhs: KeyPath<A, Int32?>, rhs: Int32?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .integer32(rhs)))
	}
	return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .null))
}
public func != <A: Codable>(lhs: KeyPath<A, Int32?>, rhs: Int?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .integer32(Int32(rhs))))
	}
	return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .null))
}
public func != <A: Codable>(lhs: KeyPath<A, UInt32?>, rhs: UInt32?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .uinteger32(rhs)))
	}
	return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .null))
}
public func != <A: Codable>(lhs: KeyPath<A, UInt32?>, rhs: Int?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .uinteger32(UInt32(rhs))))
	}
	return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .null))
}
public func != <A: Codable>(lhs: KeyPath<A, Int16?>, rhs: Int16?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .integer16(rhs)))
	}
	return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .null))
}
public func != <A: Codable>(lhs: KeyPath<A, Int16?>, rhs: Int?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .integer16(Int16(rhs))))
	}
	return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .null))
}
public func != <A: Codable>(lhs: KeyPath<A, UInt16?>, rhs: UInt16?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .uinteger16(rhs)))
	}
	return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .null))
}
public func != <A: Codable>(lhs: KeyPath<A, UInt16?>, rhs: Int?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .uinteger16(UInt16(rhs))))
	}
	return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .null))
}
public func != <A: Codable>(lhs: KeyPath<A, Int8?>, rhs: Int8?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .integer8(rhs)))
	}
	return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .null))
}
public func != <A: Codable>(lhs: KeyPath<A, Int8?>, rhs: Int?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .integer8(Int8(rhs))))
	}
	return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .null))
}
public func != <A: Codable>(lhs: KeyPath<A, UInt8?>, rhs: UInt8?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .uinteger8(rhs)))
	}
	return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .null))
}
public func != <A: Codable>(lhs: KeyPath<A, UInt8?>, rhs: Int?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .uinteger8(UInt8(rhs))))
	}
	return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .null))
}
public func != <A: Codable>(lhs: KeyPath<A, [UInt8]?>, rhs: [UInt8]?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .blob(rhs)))
	}
	return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .null))
}
public func != <A: Codable>(lhs: KeyPath<A, [Int8]?>, rhs: [Int8]?) -> CRUDBooleanExpression {
	if let rhs = rhs {
		return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .sblob(rhs)))
	}
	return RealBooleanExpression(.inequality(lhs: .keyPath(lhs), rhs: .null))
}
