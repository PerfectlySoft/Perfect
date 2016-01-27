//
//  MySQLTests.swift
//  MySQLTests
//
//  Created by Kyle Jessup on 2015-10-20.
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
@testable import MySQL

let HOST = "127.0.0.1"
let USER = "root"
let PASSWORD = ""
let SCHEMA = "test"

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
		
        let res = mysql.connect(HOST, user: USER, password: PASSWORD)
		
		XCTAssert(res)
		
		if !res {
			print(mysql.errorMessage())
			return
		}
		
		var sres = mysql.selectDatabase(SCHEMA)
        if sres == false {
            sres = mysql.query("CREATE SCHEMA `\(SCHEMA)` DEFAULT CHARACTER SET utf8mb4 ;")
        }
		
		XCTAssert(sres == true)
		
		if !sres {
			print(mysql.errorMessage())
		}
		
		mysql.close()
	}
	
	func testListDbs1() {
		
		let mysql = MySQL()
		let res = mysql.connect(HOST, user: USER, password: PASSWORD)
		
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
		let res = mysql.connect(HOST, user: USER, password: PASSWORD)
		
		XCTAssert(res)
		
		if !res {
			print(mysql.errorMessage())
		}
		
		let list = mysql.listDatabases("information_%")
		
		XCTAssert(list.count > 0)
		
		print(list)
		
		mysql.close()
	}
	
	func testListTables1() {
		
		let mysql = MySQL()
		let res = mysql.connect(HOST, user: USER, password: PASSWORD)
		
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
		let res = mysql.connect(HOST, user: USER, password: PASSWORD)
		
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
	
	func testQuery1() {
		let mysql = MySQL()
		defer {
			mysql.close()
		}
		
		let res = mysql.connect(HOST, user: USER, password: PASSWORD)
		XCTAssert(res)
		
		if !res {
			print(mysql.errorMessage())
			return
		}
		
		let sres = mysql.selectDatabase(SCHEMA)
		XCTAssert(sres == true)
		
		let qres = mysql.query("CREATE TABLE test (id INT, d DOUBLE, s VARCHAR(1024))")
		XCTAssert(qres == true, mysql.errorMessage())
		
		let list = mysql.listTables("test")
		XCTAssert(list.count > 0)
		
		for i in 1...10 {
			let ires = mysql.query("INSERT INTO test (id,d,s) VALUES (\(i),42.9,\"Row \(i)\")")
			XCTAssert(ires == true, mysql.errorMessage())
		}
		
		let sres2 = mysql.query("SELECT id,d,s FROM test")
		XCTAssert(sres2 == true, mysql.errorMessage())
		
		let results = mysql.storeResults()!
		XCTAssert(results.numRows() == 10)
		
		while let row = results.next() {
			print(row)
		}
		
		results.close()
		
		let qres2 = mysql.query("DROP TABLE test")
		XCTAssert(qres2 == true, mysql.errorMessage())
		
		let list2 = mysql.listTables("test")
		XCTAssert(list2.count == 0)
	}
	
	func testQuery2() {
		let mysql = MySQL()
		defer {
			mysql.close()
		}
		
		let res = mysql.connect(HOST, user: USER, password: PASSWORD)
		XCTAssert(res)
		
		if !res {
			print(mysql.errorMessage())
		}
		
		let sres = mysql.selectDatabase(SCHEMA)
		XCTAssert(sres == true)
		
		let qres = mysql.query("CREATE TABLE test (id INT, d DOUBLE, s VARCHAR(1024))")
		XCTAssert(qres == true, mysql.errorMessage())
		
		let list = mysql.listTables("test")
		XCTAssert(list.count > 0)
		
		for i in 1...10 {
			let ires = mysql.query("INSERT INTO test (id,d,s) VALUES (\(i),42.9,\"Row \(i)\")")
			XCTAssert(ires == true, mysql.errorMessage())
		}
		
		let sres2 = mysql.query("SELECT id,d,s FROM test")
		XCTAssert(sres2 == true, mysql.errorMessage())
		
		let results = mysql.storeResults()!
		XCTAssert(results.numRows() == 10)
		
		results.forEachRow { a in
			print(a)
		}
		
		results.close()
		
		let qres2 = mysql.query("DROP TABLE test")
		XCTAssert(qres2 == true, mysql.errorMessage())
		
		let list2 = mysql.listTables("test")
		XCTAssert(list2.count == 0)
	}
	
	func testQueryStmt1() {
		let mysql = MySQL()
		defer {
			mysql.close()
		}
		
		let res = mysql.connect(HOST, user: USER, password: PASSWORD)
		XCTAssert(res)
		
		if !res {
			print(mysql.errorMessage())
		}
		
		let sres = mysql.selectDatabase(SCHEMA)
		XCTAssert(sres == true)
		
		mysql.query("DROP TABLE IF EXISTS all_data_types")
		
		let qres = mysql.query("CREATE TABLE `all_data_types` (`varchar` VARCHAR( 20 ),\n`tinyint` TINYINT,\n`text` TEXT,\n`date` DATE,\n`smallint` SMALLINT,\n`mediumint` MEDIUMINT,\n`int` INT,\n`bigint` BIGINT,\n`float` FLOAT( 10, 2 ),\n`double` DOUBLE,\n`decimal` DECIMAL( 10, 2 ),\n`datetime` DATETIME,\n`timestamp` TIMESTAMP,\n`time` TIME,\n`year` YEAR,\n`char` CHAR( 10 ),\n`tinyblob` TINYBLOB,\n`tinytext` TINYTEXT,\n`blob` BLOB,\n`mediumblob` MEDIUMBLOB,\n`mediumtext` MEDIUMTEXT,\n`longblob` LONGBLOB,\n`longtext` LONGTEXT,\n`enum` ENUM( '1', '2', '3' ),\n`set` SET( '1', '2', '3' ),\n`bool` BOOL,\n`binary` BINARY( 20 ),\n`varbinary` VARBINARY( 20 ) ) ENGINE = MYISAM")
		XCTAssert(qres == true, mysql.errorMessage())
		
		let stmt1 = MySQLStmt(mysql)
		defer {
			stmt1.close()
		}
		let prepRes = stmt1.prepare("INSERT INTO all_data_types VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
		XCTAssert(prepRes, stmt1.errorMessage())
		XCTAssert(stmt1.paramCount() == 28)
		
		stmt1.bindParam("varchar 20 string")
		stmt1.bindParam(1)
		stmt1.bindParam("text string")
		stmt1.bindParam("2015-10-21")
		stmt1.bindParam(1)
		stmt1.bindParam(1)
		stmt1.bindParam(1)
		stmt1.bindParam(1)
		stmt1.bindParam(1.1)
		stmt1.bindParam(1.1)
		stmt1.bindParam(1.1)
		stmt1.bindParam("2015-10-21 12:00:00")
		stmt1.bindParam("2015-10-21 12:00:00")
		stmt1.bindParam("03:14:07")
		stmt1.bindParam("2015")
		stmt1.bindParam("K")
		
		"BLOB DATA".withCString { p in
			stmt1.bindParam(p, length: 9)
			
			stmt1.bindParam("tiny text string")
			
			stmt1.bindParam(p, length: 9)
			stmt1.bindParam(p, length: 9)
			
			stmt1.bindParam("medium text string")
			
			stmt1.bindParam(p, length: 9)
			
			stmt1.bindParam("long text string")
			stmt1.bindParam("1")
			stmt1.bindParam("2")
			stmt1.bindParam(1)
			stmt1.bindParam(0)
			stmt1.bindParam(1)
			
			let execRes = stmt1.execute()
			XCTAssert(execRes, "\(stmt1.errorCode()) \(stmt1.errorMessage()) - \(mysql.errorCode()) \(mysql.errorMessage())")
			
			stmt1.close()
		}
	}
	
	func testQueryStmt2() {
		let mysql = MySQL()
		defer {
			mysql.close()
		}
		
		mysql.setOption(.MYSQL_SET_CHARSET_NAME, "utf8mb4")
		let res = mysql.connect(HOST, user: USER, password: PASSWORD)
		XCTAssert(res)
		
		if !res {
			print(mysql.errorMessage())
		}
		
		let sres = mysql.selectDatabase(SCHEMA)
		XCTAssert(sres == true)
		
		mysql.query("DROP TABLE IF EXISTS all_data_types")
		
		let qres = mysql.query("CREATE TABLE `all_data_types` (`varchar` VARCHAR( 20 ),\n`tinyint` TINYINT,\n`text` TEXT,\n`date` DATE,\n`smallint` SMALLINT,\n`mediumint` MEDIUMINT,\n`int` INT,\n`bigint` BIGINT,\n`ubigint` BIGINT UNSIGNED,\n`float` FLOAT( 10, 2 ),\n`double` DOUBLE,\n`decimal` DECIMAL( 10, 2 ),\n`datetime` DATETIME,\n`timestamp` TIMESTAMP,\n`time` TIME,\n`year` YEAR,\n`char` CHAR( 10 ),\n`tinyblob` TINYBLOB,\n`tinytext` TINYTEXT,\n`blob` BLOB,\n`mediumblob` MEDIUMBLOB,\n`mediumtext` MEDIUMTEXT,\n`longblob` LONGBLOB,\n`longtext` LONGTEXT,\n`enum` ENUM( '1', '2', '3' ),\n`set` SET( '1', '2', '3' ),\n`bool` BOOL,\n`binary` BINARY( 20 ),\n`varbinary` VARBINARY( 20 ) ) ENGINE = MYISAM")
		XCTAssert(qres == true, mysql.errorMessage())
		
		for _ in 1...2 {
			let stmt1 = MySQLStmt(mysql)
			defer {
				stmt1.close()
			}
			let prepRes = stmt1.prepare("INSERT INTO all_data_types VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
			XCTAssert(prepRes, stmt1.errorMessage())
			XCTAssert(stmt1.paramCount() == 29)
			
			stmt1.bindParam("varchar 20 string 👻")
			stmt1.bindParam(1)
			stmt1.bindParam("text string")
			stmt1.bindParam("2015-10-21")
			stmt1.bindParam(32767)
			stmt1.bindParam(8388607)
            stmt1.bindParam(2147483647)
            stmt1.bindParam(9223372036854775807)
            stmt1.bindParam(18446744073709551615 as UInt64)
			stmt1.bindParam(1.1)
			stmt1.bindParam(1.1)
			stmt1.bindParam(1.1)
			stmt1.bindParam("2015-10-21 12:00:00")
			stmt1.bindParam("2015-10-21 12:00:00")
			stmt1.bindParam("03:14:07")
			stmt1.bindParam("2015")
			stmt1.bindParam("K")
			
			"BLOB DATA".withCString { p in
				stmt1.bindParam(p, length: 9)
				
				stmt1.bindParam("tiny text string")
				
				stmt1.bindParam(p, length: 9)
				stmt1.bindParam(p, length: 9)
				
				stmt1.bindParam("medium text string")
				
				stmt1.bindParam(p, length: 9)
				
				stmt1.bindParam("long text string")
				stmt1.bindParam("1")
				stmt1.bindParam("2")
				stmt1.bindParam(1)
				stmt1.bindParam(1)
				stmt1.bindParam(1)
				
				let execRes = stmt1.execute()
				XCTAssert(execRes, "\(stmt1.errorCode()) \(stmt1.errorMessage()) - \(mysql.errorCode()) \(mysql.errorMessage())")
				
				stmt1.close()
			}
		}
		
		do {
			let stmt1 = MySQLStmt(mysql)
			
			let prepRes = stmt1.prepare("SELECT * FROM all_data_types")
			XCTAssert(prepRes, stmt1.errorMessage())
			
			let execRes = stmt1.execute()
			XCTAssert(execRes, stmt1.errorMessage())
			
			let results = stmt1.results()
			
			let ok = results.forEachRow {
				e in
				print(e.flatMap({ (a:Any?) -> Any? in
					return a!
				}))
			}
			XCTAssert(ok, stmt1.errorMessage())
			
			results.close()
			stmt1.close()
		}
	}
	
	func testServerVersion() {
		let mysql = MySQL()
		defer {
			mysql.close()
		}
		let res = mysql.connect(HOST, user: USER, password: PASSWORD)
		XCTAssert(res)
		
		if !res {
			print(mysql.errorMessage())
		}
		
		let vers = mysql.serverVersion()
		XCTAssert(vers >= 50627) // YMMV
	}
	
	
	
}





























