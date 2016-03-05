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
        XCTAssert(mysql.connect(HOST, user: USER, password: PASSWORD), mysql.errorMessage())
        if mysql.selectDatabase(SCHEMA) == false {
            XCTAssert(mysql.query("CREATE SCHEMA `\(SCHEMA)` DEFAULT CHARACTER SET utf8mb4"), mysql.errorMessage())
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

    /*
    try dbManager.query("CREATE TABLE IF NOT EXISTS `all_data_types` (`char` CHAR( 10 ),`varchar` VARCHAR( 20 ),`tinytext` TINYTEXT,`mediumtext` MEDIUMTEXT,`text` TEXT,`longtext` LONGTEXT,"
    + "`tinyint` TINYINT,`utinyint` TINYINT UNSIGNED,`smallint` SMALLINT,`usmallint` SMALLINT UNSIGNED,`mediumint` MEDIUMINT,`umediumint` MEDIUMINT UNSIGNED,"
    + "`int` INT,`uint` INT UNSIGNED,`bigint` BIGINT,`ubigint` BIGINT UNSIGNED,"
    + "`float` FLOAT( 10, 2 ),`double` DOUBLE,`decimal` DECIMAL( 10, 2 ),"
    + "`date` DATE,`datetime` DATETIME,`timestamp` TIMESTAMP,`time` TIME,`year` YEAR,"
    + "`tinyblob` TINYBLOB,`mediumblob` MEDIUMBLOB,`blob` BLOB,`longblob` LONGBLOB,"
    + "`enum` ENUM( '1', '2', '3' ),`set` SET( '1', '2', '3' ),`bool` BOOL,"
    + "`binary` BINARY( 20 ),`varbinary` VARBINARY( 20 ) )")
    
    try dbManager.query("DELETE FROM all_data_types")
    
    try dbManager.query("INSERT INTO all_data_types (`char`,`varchar`,`tinytext`,`mediumtext`,`text`,`longtext`,"
    + "`tinyint`,`utinyint`,`smallint`,`usmallint`,`mediumint`,`umediumint`,"
    + "`int`,`uint`,`bigint`,`ubigint`,"
    + "`float`, `double`, `decimal`,"
    + "`date`, `datetime`, `timestamp`, `time`,`year`,"
    + "`tinyblob`, `mediumblob`, `blob`,`longblob`,"
    + "`enum`,`set`,`bool`,"
    + "`binary`,`varbinary` ) VALUES ("
    + "'a','abc','tiny text','medium text','text','long text',"
    + "-1, 1, -2, 2, -3, 3,"
    + "-4, 4, -5, 5,"
    + "1.1, 2.2, 123,"
    + "'2015-10-21','2015-10-21 11:22:33','2015-10-21 11:22:33','11:22:33','2016',"
    + "'abc','abc','abc','abc',"
    + "'1','2',true,"
    + "'1','2')")
    try dbManager.query("SELECT * FROM all_data_types LIMIT 1")
    let results = try dbManager.storeResults()
    defer { results.close() }
    while let row = results.next() {
    print(row)
    }
    
    try dbManager.query("DELETE FROM all_data_types")
    
    
    let stmt1 = MySQLStmt(dbManager.db)
    defer { stmt1.close() }
    let prepRes = stmt1.prepare("INSERT INTO all_data_types VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
    //        print(prepRes)
    stmt1.bindParam("a")
    stmt1.bindParam("abc")
    stmt1.bindParam("tiny text")
    stmt1.bindParam("medium text")
    stmt1.bindParam("text")
    stmt1.bindParam("long text")
    stmt1.bindParam(-1)
    stmt1.bindParam(1)
    stmt1.bindParam(-2)
    stmt1.bindParam(2)
    stmt1.bindParam(-3)
    stmt1.bindParam(3)
    stmt1.bindParam(-4)
    stmt1.bindParam(4)
    stmt1.bindParam(-5)
    stmt1.bindParam(5)
    stmt1.bindParam(1.1)
    stmt1.bindParam(2.2)
    stmt1.bindParam(123)
    stmt1.bindParam("2015-10-21")
    stmt1.bindParam("2015-10-21 11:22:33")
    stmt1.bindParam("2015-10-21 11:22:33")
    stmt1.bindParam("11:22:33")
    stmt1.bindParam("2016")
    
    stmt1.bindParam("tinyblob👻")
    stmt1.bindParam("mediumblob")
    stmt1.bindParam("blob")
    stmt1.bindParam("longblob")
    //        "tinyblob".withCString { stmt1.bindParam($0, length: 8) }
    //        "mediumblob".withCString { stmt1.bindParam($0, length: 10) }
    //        "blob".withCString { stmt1.bindParam($0, length: 4) }
    //        "longblob".withCString { stmt1.bindParam($0, length: 8) }
    stmt1.bindParam("1")
    stmt1.bindParam("2")
    stmt1.bindParam(1)
    stmt1.bindParam("1")
    stmt1.bindParam("2")
    let execRes = stmt1.execute()
    //        print(execRes)
    let stmt2 = MySQLStmt(dbManager.db)
    defer { stmt2.close() }
    //        let prepRes2 = stmt2.prepare("SELECT `text`, 'blob' FROM all_data_types")
    let prepRes2 = stmt2.prepare("SELECT * FROM all_data_types")
    //        print(prepRes2)
    let execRes2 = stmt2.execute()
    let results2 = stmt2.results()
    defer { results2.close() }
    results2.forEachRow { row in
    //            print("text", UTF8Encoding.encode(row[0] as! [UInt8]))
    //            print("blob", row[1] as! String)
    
    print("char", row[0] as! String)
    print("varchar", row[1] as! String)
    print("tinytext", UTF8Encoding.encode(row[2] as! [UInt8]))
    print("mediumtext", UTF8Encoding.encode(row[3] as! [UInt8]))
    print("text", UTF8Encoding.encode(row[4] as! [UInt8]))
    print("longtext", UTF8Encoding.encode(row[5] as! [UInt8]))
    print("tinyint", row[6] as! Int8)
    print("utinyint", row[7] as! UInt8)
    print("smallint", row[8] as! Int16)
    print("usmallint", row[9] as! UInt16)
    print("mediumint", row[10] as! Int32)
    print("umediumint", row[11] as! UInt32)
    print("int", row[12] as! Int32)
    print("uint", row[13] as! UInt32)
    print("bigint", row[14] as! Int64)
    print("ubigint", row[15] as! UInt64)
    print("float", row[16] as! Float)
    print("double", row[17] as! Double)
    print("decimal", row[18] as! String)
    print("date", row[19] as! String)
    print("datetime", row[20] as! String)
    print("timestamp", row[21] as! String)
    print("time", row[22] as! String)
    print("year", row[23] as! String)
    print("tinyblob", UTF8Encoding.encode(row[24] as! [UInt8]))
    print("mediumblob", UTF8Encoding.encode(row[25] as! [UInt8]))
    print("blob", UTF8Encoding.encode(row[26] as! [UInt8]))
    print("longblob", UTF8Encoding.encode(row[27] as! [UInt8]))
    print("enum", row[28] as! String)
    print("set", row[29] as! String)
    print("bool", row[30] as! Int8)
    print("binary", row[31] as! String)
    print("varbinary", row[32] as! String)
    }
*/
}





























