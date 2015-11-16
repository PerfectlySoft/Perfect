//
//  PostgreSQLTests.swift
//  PostgreSQLTests
//
//  Created by Kyle Jessup on 2015-10-19.
//  Copyright © 2015 PerfectlySoft. All rights reserved.
//
//	This program is free software: you can redistribute it and/or modify
//	it under the terms of the GNU Affero General Public License as
//	published by the Free Software Foundation, either version 3 of the
//	License, or (at your option) any later version, as supplemented by the
//	Perfect Additional Terms.
//
//	This program is distributed in the hope that it will be useful,
//	but WITHOUT ANY WARRANTY; without even the implied warranty of
//	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//	GNU Affero General Public License, as supplemented by the
//	Perfect Additional Terms, for more details.
//
//	You should have received a copy of the GNU Affero General Public License
//	and the Perfect Additional Terms that immediately follow the terms and
//	conditions of the GNU Affero General Public License along with this
//	program. If not, see <http://www.perfect.org/AGPL_3_0_With_Perfect_Additional_Terms.txt>.
//

import XCTest
@testable import PostgreSQL

class PostgreSQLTests: XCTestCase {
	
	override func setUp() {
		super.setUp()
		// Put setup code here. This method is called before the invocation of each test method in the class.
	}
	
	override func tearDown() {
		// Put teardown code here. This method is called after the invocation of each test method in the class.
		super.tearDown()
	}
	
	func testConnect() {
		let p = PGConnection()
		p.connectdb("dbname = postgres")
		let status = p.status()
		
		XCTAssert(status == .OK)
		
		p.finish()
	}
	
	func testExec() {
		let p = PGConnection()
		p.connectdb("dbname = postgres")
		let status = p.status()
		XCTAssert(status == .OK)
		
		let res = p.exec("select * from pg_database")
		XCTAssertEqual(res.status(), PGResult.StatusType.TuplesOK)
		
		let num = res.numFields()
		XCTAssert(num > 0)
		for x in 0..<num {
			let fn = res.fieldName(x)
			XCTAssertNotNil(fn)
			print(fn!)
		}
		res.clear()
		p.finish()
	}
	
	func testExecGetValues() {
		let p = PGConnection()
		p.connectdb("dbname = postgres")
		let status = p.status()
		XCTAssert(status == .OK)
		// name, oid, integer, boolean
		let res = p.exec("select datname,datdba,encoding,datistemplate from pg_database")
		XCTAssertEqual(res.status(), PGResult.StatusType.TuplesOK)
		
		let num = res.numTuples()
		XCTAssert(num > 0)
		for x in 0..<num {
			let c1 = res.getFieldString(x, fieldIndex: 0)
			XCTAssertTrue(c1.characters.count > 0)
			let c2 = res.getFieldInt(x, fieldIndex: 1)
			let c3 = res.getFieldInt(x, fieldIndex: 2)
			let c4 = res.getFieldBool(x, fieldIndex: 3)
			print("c1=\(c1) c2=\(c2) c3=\(c3) c4=\(c4)")
		}
		res.clear()
		p.finish()
	}
	
	func testExecGetValuesParams() {
		let p = PGConnection()
		p.connectdb("dbname = postgres")
		let status = p.status()
		XCTAssert(status == .OK)
		// name, oid, integer, boolean
		let res = p.exec("select datname,datdba,encoding,datistemplate from pg_database where encoding = $1", params: ["6"])
		XCTAssertEqual(res.status(), PGResult.StatusType.TuplesOK, res.errorMessage())
		
		let num = res.numTuples()
		XCTAssert(num > 0)
		for x in 0..<num {
			let c1 = res.getFieldString(x, fieldIndex: 0)
			XCTAssertTrue(c1.characters.count > 0)
			let c2 = res.getFieldInt(x, fieldIndex: 1)
			let c3 = res.getFieldInt(x, fieldIndex: 2)
			let c4 = res.getFieldBool(x, fieldIndex: 3)
			print("c1=\(c1) c2=\(c2) c3=\(c3) c4=\(c4)")
		}
		res.clear()
		p.finish()
	}
}
