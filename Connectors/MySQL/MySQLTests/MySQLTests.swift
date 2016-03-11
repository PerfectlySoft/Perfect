//
//  MySQLTests.swift
//  MySQLTests
//
//  Created by Kyle Jessup on 2015-10-20.
//  Copyright © 2015 PerfectlySoft. All rights reserved.
//
//===----------------------------------------------------------------------===//
//
// This source file is part of the Perfect.org open source project
//
// Copyright (c) 2015 - 2016 PerfectlySoft Inc. and the Perfect project authors
// Licensed under Apache License v2.0
//
// See http://perfect.org/licensing.html for license information
//
//===----------------------------------------------------------------------===//
//

import XCTest
import PerfectLib
@testable import MySQL

let HOST = "127.0.0.1"
let USER = "root"
let PASSWORD = ""
let SCHEMA = "test"

class MySQLTests: XCTestCase {
    var mysql: MySQL!

    override func setUp() {
        super.setUp()

        //  connect and select DB
        mysql = MySQL()
        XCTAssert(mysql.setOption(.MYSQL_SET_CHARSET_NAME, "utf8mb4"), mysql.errorMessage())
        XCTAssert(mysql.connect(HOST, user: USER, password: PASSWORD), mysql.errorMessage())
        if mysql.selectDatabase(SCHEMA) == false {
            XCTAssert(mysql.query("CREATE SCHEMA `\(SCHEMA)` DEFAULT CHARACTER SET utf8mb4"), mysql.errorMessage())
            XCTAssert(mysql.selectDatabase(SCHEMA), mysql.errorMessage())
        }
    }
    
    override func tearDown() {
        super.tearDown()

        //  close
        if let mysql = mysql {
            mysql.close()
        }
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
		let list = mysql.listDatabases()
		
		XCTAssert(list.count > 0)
		
		print(list)
	}
	
	func testListDbs2() {
		let list = mysql.listDatabases("information_%")
		
		XCTAssert(list.count > 0)
		
		print(list)
	}
	
	func testListTables1() {
		let sres = mysql.selectDatabase("information_schema")
		
		XCTAssert(sres == true)
		
		let list = mysql.listTables()
		
		XCTAssert(list.count > 0)
		
		print(list)
	}
	
	func testListTables2() {
		let sres = mysql.selectDatabase("information_schema")
		
		XCTAssert(sres == true)
		
		let list = mysql.listTables("INNODB_%")
		
		XCTAssert(list.count > 0)
		
		print(list)
	}
	
	func testQuery1() {
        mysql.query("DROP TABLE IF EXISTS test")

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
        mysql.query("DROP TABLE IF EXISTS test")

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
		mysql.query("DROP TABLE IF EXISTS all_data_types")
		
		let qres = mysql.query("CREATE TABLE `all_data_types` (`varchar` VARCHAR( 20 ),\n`tinyint` TINYINT,\n`text` TEXT,\n`date` DATE,\n`smallint` SMALLINT,\n`mediumint` MEDIUMINT,\n`int` INT,\n`bigint` BIGINT,\n`float` FLOAT( 10, 2 ),\n`double` DOUBLE,\n`decimal` DECIMAL( 10, 2 ),\n`datetime` DATETIME,\n`timestamp` TIMESTAMP,\n`time` TIME,\n`year` YEAR,\n`char` CHAR( 10 ),\n`tinyblob` TINYBLOB,\n`tinytext` TINYTEXT,\n`blob` BLOB,\n`mediumblob` MEDIUMBLOB,\n`mediumtext` MEDIUMTEXT,\n`longblob` LONGBLOB,\n`longtext` LONGTEXT,\n`enum` ENUM( '1', '2', '3' ),\n`set` SET( '1', '2', '3' ),\n`bool` BOOL,\n`binary` BINARY( 20 ),\n`varbinary` VARBINARY( 20 ) ) ENGINE = MYISAM")
		XCTAssert(qres == true, mysql.errorMessage())
		
		let stmt1 = MySQLStmt(mysql)
		defer { stmt1.close() }
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
		}
	}
	
	func testQueryStmt2() {
		mysql.query("DROP TABLE IF EXISTS all_data_types")
		
		let qres = mysql.query("CREATE TABLE `all_data_types` (`varchar` VARCHAR( 20 ),\n`tinyint` TINYINT,\n`text` TEXT,\n`date` DATE,\n`smallint` SMALLINT,\n`mediumint` MEDIUMINT,\n`int` INT,\n`bigint` BIGINT,\n`ubigint` BIGINT UNSIGNED,\n`float` FLOAT( 10, 2 ),\n`double` DOUBLE,\n`decimal` DECIMAL( 10, 2 ),\n`datetime` DATETIME,\n`timestamp` TIMESTAMP,\n`time` TIME,\n`year` YEAR,\n`char` CHAR( 10 ),\n`tinyblob` TINYBLOB,\n`tinytext` TINYTEXT,\n`blob` BLOB,\n`mediumblob` MEDIUMBLOB,\n`mediumtext` MEDIUMTEXT,\n`longblob` LONGBLOB,\n`longtext` LONGTEXT,\n`enum` ENUM( '1', '2', '3' ),\n`set` SET( '1', '2', '3' ),\n`bool` BOOL,\n`binary` BINARY( 20 ),\n`varbinary` VARBINARY( 20 ) ) ENGINE = MYISAM")
		XCTAssert(qres == true, mysql.errorMessage())
		
		for _ in 1...2 {
			let stmt1 = MySQLStmt(mysql)
            defer { stmt1.close() }
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
			}
		}
		
		do {
			let stmt1 = MySQLStmt(mysql)
            defer { stmt1.close() }
			
			let prepRes = stmt1.prepare("SELECT * FROM all_data_types")
			XCTAssert(prepRes, stmt1.errorMessage())
			
			let execRes = stmt1.execute()
			XCTAssert(execRes, stmt1.errorMessage())
			
			let results = stmt1.results()
            defer { results.close() }
			
			let ok = results.forEachRow {
				e in
				print(e.flatMap({ (a:Any?) -> Any? in
					return a!
				}))
                
                XCTAssertEqual(e[0] as? String, "varchar 20 string 👻")
                XCTAssertEqual(e[1] as? Int8, 1)
                XCTAssertEqual(UTF8Encoding.encode(e[2] as! [UInt8]), "text string")
                XCTAssertEqual(e[3] as? String, "2015-10-21")
                XCTAssertEqual(e[4] as? Int16, 32767)
                XCTAssertEqual(e[5] as? Int32, 8388607)
                XCTAssertEqual(e[6] as? Int32, 2147483647)
                XCTAssertEqual(e[7] as? Int64, 9223372036854775807)
                XCTAssertEqual(e[8] as? UInt64, 18446744073709551615 as UInt64)
                XCTAssertEqual(e[9] as? Float, 1.1)
                XCTAssertEqual(e[10] as? Double, 1.1)
                XCTAssertEqual(e[11] as? String, "1.10")
                XCTAssertEqual(e[12] as? String, "2015-10-21 12:00:00")
                XCTAssertEqual(e[13] as? String, "2015-10-21 12:00:00")
                XCTAssertEqual(e[14] as? String, "03:14:07")
                XCTAssertEqual(e[15] as? String, "2015")
                XCTAssertEqual(e[16] as? String, "K")
                XCTAssertEqual(UTF8Encoding.encode(e[17] as! [UInt8]), "BLOB DATA")
                XCTAssertEqual(UTF8Encoding.encode(e[18] as! [UInt8]), "tiny text string")
                XCTAssertEqual(UTF8Encoding.encode(e[19] as! [UInt8]), "BLOB DATA")
                XCTAssertEqual(UTF8Encoding.encode(e[20] as! [UInt8]), "BLOB DATA")
                XCTAssertEqual(UTF8Encoding.encode(e[21] as! [UInt8]), "medium text string")
                XCTAssertEqual(UTF8Encoding.encode(e[22] as! [UInt8]), "BLOB DATA")
                XCTAssertEqual(UTF8Encoding.encode(e[23] as! [UInt8]), "long text string")
                XCTAssertEqual(e[24] as? String, "1")
                XCTAssertEqual(e[25] as? String, "2")
                XCTAssertEqual(e[26] as? Int8, 1)
                XCTAssertEqual(e[27] as? String, "1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0")
                XCTAssertEqual(e[28] as? String, "1")
			}
			XCTAssert(ok, stmt1.errorMessage())
		}
	}
	
	func testServerVersion() {
		let vers = mysql.serverVersion()
		XCTAssert(vers >= 50627) // YMMV
	}
	
    func testQueryInt() {
        XCTAssert(mysql.query("DROP TABLE IF EXISTS int_test"), mysql.errorMessage())
        XCTAssert(mysql.query("CREATE TABLE int_test (a TINYINT, au TINYINT UNSIGNED, b SMALLINT, bu SMALLINT UNSIGNED, c MEDIUMINT, cu MEDIUMINT UNSIGNED, d INT, du INT UNSIGNED, e BIGINT, eu BIGINT UNSIGNED)"), mysql.errorMessage())

        var qres = mysql.query("INSERT INTO int_test (a, au, b, bu, c, cu, d, du, e, eu) VALUES "
            + "(-1, 1, -2, 2, -3, 3, -4, 4, -5, 5)")
        XCTAssert(qres == true, mysql.errorMessage())
        
        qres =  mysql.query("SELECT * FROM int_test")
        XCTAssert(qres == true, mysql.errorMessage())

        let results = mysql.storeResults()
        if let results = results {
            defer { results.close() }
            while let row = results.next() {
                XCTAssertEqual(row[0], "-1")
                XCTAssertEqual(row[1], "1")
                XCTAssertEqual(row[2], "-2")
                XCTAssertEqual(row[3], "2")
                XCTAssertEqual(row[4], "-3")
                XCTAssertEqual(row[5], "3")
                XCTAssertEqual(row[6], "-4")
                XCTAssertEqual(row[7], "4")
                XCTAssertEqual(row[8], "-5")
                XCTAssertEqual(row[9], "5")
            }
        }
    }
 
    func testQueryIntMin() {
        XCTAssert(mysql.query("DROP TABLE IF EXISTS int_test"), mysql.errorMessage())
        XCTAssert(mysql.query("CREATE TABLE int_test (a TINYINT, au TINYINT UNSIGNED, b SMALLINT, bu SMALLINT UNSIGNED, c MEDIUMINT, cu MEDIUMINT UNSIGNED, d INT, du INT UNSIGNED, e BIGINT, eu BIGINT UNSIGNED)"), mysql.errorMessage())
        
        var qres = mysql.query("INSERT INTO int_test (a, au, b, bu, c, cu, d, du, e, eu) VALUES "
            + "(-128, 0, -32768, 0, -8388608, 0, -2147483648, 0, -9223372036854775808, 0)")
        XCTAssert(qres == true, mysql.errorMessage())
        
        qres =  mysql.query("SELECT * FROM int_test")
        XCTAssert(qres == true, mysql.errorMessage())
        
        let results = mysql.storeResults()
        if let results = results {
            defer { results.close() }
            while let row = results.next() {
                XCTAssertEqual(row[0], "-128")
                XCTAssertEqual(row[1], "0")
                XCTAssertEqual(row[2], "-32768")
                XCTAssertEqual(row[3], "0")
                XCTAssertEqual(row[4], "-8388608")
                XCTAssertEqual(row[5], "0")
                XCTAssertEqual(row[6], "-2147483648")
                XCTAssertEqual(row[7], "0")
                XCTAssertEqual(row[8], "-9223372036854775808")
                XCTAssertEqual(row[9], "0")
            }
        }
    }
    
    func testQueryIntMax() {
        XCTAssert(mysql.query("DROP TABLE IF EXISTS int_test"), mysql.errorMessage())
        XCTAssert(mysql.query("CREATE TABLE int_test (a TINYINT, au TINYINT UNSIGNED, b SMALLINT, bu SMALLINT UNSIGNED, c MEDIUMINT, cu MEDIUMINT UNSIGNED, d INT, du INT UNSIGNED, e BIGINT, eu BIGINT UNSIGNED)"), mysql.errorMessage())
        
        var qres = mysql.query("INSERT INTO int_test (a, au, b, bu, c, cu, d, du, e, eu) VALUES "
            + "(127, 255, 32767, 65535, 8388607, 16777215, 2147483647, 4294967295, 9223372036854775807, 18446744073709551615)")
        XCTAssert(qres == true, mysql.errorMessage())
        
        qres =  mysql.query("SELECT * FROM int_test")
        XCTAssert(qres == true, mysql.errorMessage())
        
        let results = mysql.storeResults()
        if let results = results {
            defer { results.close() }
            while let row = results.next() {
                XCTAssertEqual(row[0], "127")
                XCTAssertEqual(row[1], "255")
                XCTAssertEqual(row[2], "32767")
                XCTAssertEqual(row[3], "65535")
                XCTAssertEqual(row[4], "8388607")
                XCTAssertEqual(row[5], "16777215")
                XCTAssertEqual(row[6], "2147483647")
                XCTAssertEqual(row[7], "4294967295")
                XCTAssertEqual(row[8], "9223372036854775807")
                XCTAssertEqual(row[9], "18446744073709551615")
            }
        }
    }
    
    func testQueryDecimal() {
        XCTAssert(mysql.query("DROP TABLE IF EXISTS decimal_test"), mysql.errorMessage())
        XCTAssert(mysql.query("CREATE TABLE decimal_test (f FLOAT, fm FLOAT, d DOUBLE, dm DOUBLE, de DECIMAL(2,1), dem DECIMAL(2,1))"), mysql.errorMessage())
        
        var qres = mysql.query("INSERT INTO decimal_test (f, fm, d, dm, de, dem) VALUES "
            + "(1.1, -1.1, 2.2, -2.2, 3.3, -3.3)")
        XCTAssert(qres == true, mysql.errorMessage())
        
        qres =  mysql.query("SELECT * FROM decimal_test")
        XCTAssert(qres == true, mysql.errorMessage())
        
        let results = mysql.storeResults()
        if let results = results {
            defer { results.close() }
            while let row = results.next() {
                XCTAssertEqual(row[0], "1.1")
                XCTAssertEqual(row[1], "-1.1")
                XCTAssertEqual(row[2], "2.2")
                XCTAssertEqual(row[3], "-2.2")
                XCTAssertEqual(row[4], "3.3")
                XCTAssertEqual(row[5], "-3.3")
            }
        }
    }
    
    func testStmtInt() {
        XCTAssert(mysql.query("DROP TABLE IF EXISTS int_test"), mysql.errorMessage())
        XCTAssert(mysql.query("CREATE TABLE int_test (a TINYINT, au TINYINT UNSIGNED, b SMALLINT, bu SMALLINT UNSIGNED, c MEDIUMINT, cu MEDIUMINT UNSIGNED, d INT, du INT UNSIGNED, e BIGINT, eu BIGINT UNSIGNED)"), mysql.errorMessage())
        
        let stmt = MySQLStmt(mysql)
        defer { stmt.close() }
        var res = stmt.prepare("INSERT INTO int_test (a, au, b, bu, c, cu, d, du, e, eu) VALUES "
            + "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        XCTAssert(res == true, stmt.errorMessage())

        stmt.bindParam(-1)
        stmt.bindParam(1)
        stmt.bindParam(-2)
        stmt.bindParam(2)
        stmt.bindParam(-3)
        stmt.bindParam(3)
        stmt.bindParam(-4)
        stmt.bindParam(4)
        stmt.bindParam(-5)
        stmt.bindParam(5)

        res = stmt.execute()
        XCTAssert(res == true, stmt.errorMessage())

        stmt.reset()
        res = stmt.prepare("SELECT * FROM int_test")
        XCTAssert(res == true, stmt.errorMessage())

        res = stmt.execute()
        XCTAssert(res == true, stmt.errorMessage())
        
        let results = stmt.results()
        defer { results.close() }
        results.forEachRow { row in
            XCTAssertEqual(row[0] as? Int8, -1)
            XCTAssertEqual(row[1] as? UInt8, 1)
            XCTAssertEqual(row[2] as? Int16, -2)
            XCTAssertEqual(row[3] as? UInt16, 2)
            XCTAssertEqual(row[4] as? Int32, -3)
            XCTAssertEqual(row[5] as? UInt32, 3)
            XCTAssertEqual(row[6] as? Int32, -4)
            XCTAssertEqual(row[7] as? UInt32, 4)
            XCTAssertEqual(row[8] as? Int64, -5)
            XCTAssertEqual(row[9] as? UInt64, 5)
        }
    }

    func testStmtIntMin() {
        XCTAssert(mysql.query("DROP TABLE IF EXISTS int_test"), mysql.errorMessage())
        XCTAssert(mysql.query("CREATE TABLE int_test (a TINYINT, au TINYINT UNSIGNED, b SMALLINT, bu SMALLINT UNSIGNED, c MEDIUMINT, cu MEDIUMINT UNSIGNED, d INT, du INT UNSIGNED, e BIGINT, eu BIGINT UNSIGNED)"), mysql.errorMessage())
        
        let stmt = MySQLStmt(mysql)
        defer { stmt.close() }
        var res = stmt.prepare("INSERT INTO int_test (a, au, b, bu, c, cu, d, du, e, eu) VALUES "
            + "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        XCTAssert(res == true, stmt.errorMessage())

        stmt.bindParam(-128)
        stmt.bindParam(0)
        stmt.bindParam(-32768)
        stmt.bindParam(0)
        stmt.bindParam(-8388608)
        stmt.bindParam(0)
        stmt.bindParam(-2147483648)
        stmt.bindParam(0)
        stmt.bindParam(-9223372036854775808)
        stmt.bindParam(0)
        
        res = stmt.execute()
        XCTAssert(res == true, stmt.errorMessage())
        
        stmt.reset()
        res = stmt.prepare("SELECT * FROM int_test")
        XCTAssert(res == true, stmt.errorMessage())
        
        res = stmt.execute()
        XCTAssert(res == true, stmt.errorMessage())
        
        let results = stmt.results()
        defer { results.close() }
        results.forEachRow { row in
            XCTAssertEqual(row[0] as? Int8, -128)
            XCTAssertEqual(row[1] as? UInt8, 0)
            XCTAssertEqual(row[2] as? Int16, -32768)
            XCTAssertEqual(row[3] as? UInt16, 0)
            XCTAssertEqual(row[4] as? Int32, -8388608)
            XCTAssertEqual(row[5] as? UInt32, 0)
            XCTAssertEqual(row[6] as? Int32, -2147483648)
            XCTAssertEqual(row[7] as? UInt32, 0)
            XCTAssertEqual(row[8] as? Int64, -9223372036854775808)
            XCTAssertEqual(row[9] as? UInt64, 0)
        }
    }
    
    func testStmtIntMax() {
        XCTAssert(mysql.query("DROP TABLE IF EXISTS int_test"), mysql.errorMessage())
        XCTAssert(mysql.query("CREATE TABLE int_test (a TINYINT, au TINYINT UNSIGNED, b SMALLINT, bu SMALLINT UNSIGNED, c MEDIUMINT, cu MEDIUMINT UNSIGNED, d INT, du INT UNSIGNED, e BIGINT, eu BIGINT UNSIGNED)"), mysql.errorMessage())
        
        let stmt = MySQLStmt(mysql)
        defer { stmt.close() }
        var res = stmt.prepare("INSERT INTO int_test (a, au, b, bu, c, cu, d, du, e, eu) VALUES "
            + "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        XCTAssert(res == true, stmt.errorMessage())
        
        stmt.bindParam(127)
        stmt.bindParam(255)
        stmt.bindParam(32767)
        stmt.bindParam(65535)
        stmt.bindParam(8388607)
        stmt.bindParam(16777215)
        stmt.bindParam(2147483647)
        stmt.bindParam(4294967295)
        stmt.bindParam(9223372036854775807)
        stmt.bindParam(18446744073709551615 as UInt64)
        
        res = stmt.execute()
        XCTAssert(res == true, stmt.errorMessage())
        
        stmt.reset()
        res = stmt.prepare("SELECT * FROM int_test")
        XCTAssert(res == true, stmt.errorMessage())
        
        res = stmt.execute()
        XCTAssert(res == true, stmt.errorMessage())
        
        let results = stmt.results()
        defer { results.close() }
        results.forEachRow { row in
            XCTAssertEqual(row[0] as? Int8, 127)
            XCTAssertEqual(row[1] as? UInt8, 255)
            XCTAssertEqual(row[2] as? Int16, 32767)
            XCTAssertEqual(row[3] as? UInt16, 65535)
            XCTAssertEqual(row[4] as? Int32, 8388607)
            XCTAssertEqual(row[5] as? UInt32, 16777215)
            XCTAssertEqual(row[6] as? Int32, 2147483647)
            XCTAssertEqual(row[7] as? UInt32, 4294967295)
            XCTAssertEqual(row[8] as? Int64, 9223372036854775807)
            XCTAssertEqual(row[9] as? UInt64, 18446744073709551615)
        }
    }
    
    func testStmtDecimal() {
        XCTAssert(mysql.query("DROP TABLE IF EXISTS decimal_test"), mysql.errorMessage())
        XCTAssert(mysql.query("CREATE TABLE decimal_test (f FLOAT, fm FLOAT, d DOUBLE, dm DOUBLE, de DECIMAL(2,1), dem DECIMAL(2,1))"), mysql.errorMessage())
        
        let stmt = MySQLStmt(mysql)
        defer { stmt.close() }
        var res = stmt.prepare("INSERT INTO decimal_test (f, fm, d, dm, de, dem) VALUES "
            + "(?, ?, ?, ?, ?, ?)")
        XCTAssert(res == true, stmt.errorMessage())
        
        stmt.bindParam(1.1)
        stmt.bindParam(-1.1)
        stmt.bindParam(2.2)
        stmt.bindParam(-2.2)
        stmt.bindParam(3.3)
        stmt.bindParam(-3.3)
        
        res = stmt.execute()
        XCTAssert(res == true, stmt.errorMessage())
        
        stmt.reset()
        res = stmt.prepare("SELECT * FROM decimal_test")
        XCTAssert(res == true, stmt.errorMessage())
        
        res = stmt.execute()
        XCTAssert(res == true, stmt.errorMessage())
        
        let results = stmt.results()
        defer { results.close() }
        results.forEachRow { row in
            print(row)
            XCTAssertEqual(row[0] as? Float, 1.1)
            XCTAssertEqual(row[1] as? Float, -1.1)
            XCTAssertEqual(row[2] as? Double, 2.2)
            XCTAssertEqual(row[3] as? Double, -2.2)
            XCTAssertEqual(row[4] as? String, "3.3")
            XCTAssertEqual(row[5] as? String, "-3.3")
        }
    }
}
