//
//  MySQLTests.swift
//  MySQLTests
//
//  Created by Kyle Jessup on 2015-10-20.
//  Copyright © 2015 PerfectlySoft. All rights reserved.
//

import XCTest
@testable import MySQL

class MySQLTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testConnect() {
		
		let mysql = MySQL()
		
		XCTAssert(mysql.setOption(.MYSQL_OPT_RECONNECT, true) == true)
		XCTAssert(mysql.setOption(.MYSQL_OPT_LOCAL_INFILE) == true)
		XCTAssert(mysql.setOption(.MYSQL_OPT_CONNECT_TIMEOUT, 5) == true)
		
		let res = mysql.connect("localhost")
		
		XCTAssert(res)
		
		if !res {
			print(mysql.errorMessage())
		}
		
		let sres = mysql.selectDatabase("test")
		
		XCTAssert(sres == true)
		
		if !sres {
			print(mysql.errorMessage())
		}
		
		mysql.close()
	}
	
	func testListDbs() {
		
		let mysql = MySQL()
		let res = mysql.connect()
		
		XCTAssert(res)
		
		if !res {
			print(mysql.errorMessage())
		}
		
		let list = mysql.listDatabases()
		
		XCTAssert(list.count > 0)
		
		print(list)
		
		mysql.close()
	}
	
	func testListDbs2() {
		
		let mysql = MySQL()
		let res = mysql.connect()
		
		XCTAssert(res)
		
		if !res {
			print(mysql.errorMessage())
		}
		
		let list = mysql.listDatabases("information_%")
		
		XCTAssert(list.count > 0)
		
		print(list)
		
		mysql.close()
	}
	
	func testListTables() {
		
		let mysql = MySQL()
		let res = mysql.connect()
		
		XCTAssert(res)
		
		if !res {
			print(mysql.errorMessage())
		}
		
		let sres = mysql.selectDatabase("information_schema")
		
		XCTAssert(sres == true)
		
		let list = mysql.listTables()
		
		XCTAssert(list.count > 0)
		
		print(list)
		
		mysql.close()
	}
	
	func testListTables2() {
		
		let mysql = MySQL()
		let res = mysql.connect()
		
		XCTAssert(res)
		
		if !res {
			print(mysql.errorMessage())
		}
		
		let sres = mysql.selectDatabase("information_schema")
		
		XCTAssert(sres == true)
		
		let list = mysql.listTables("INNODB_%")
		
		XCTAssert(list.count > 0)
		
		print(list)
		
		mysql.close()
	}
}





