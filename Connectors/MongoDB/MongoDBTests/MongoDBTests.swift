//
//  MongoDBTests.swift
//  MongoDBTests
//
//  Created by Kyle Jessup on 2015-11-18.
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
@testable import MongoDB

class MongoDBTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testBSONFromJSON() {
		let json = "{\"id\":1,\"first_name\":\"Kimberly\",\"last_name\":\"Gonzales\",\"email\":\"kgonzales0@usnews.com\",\"country\":\"France\",\"ip_address\":\"164.55.182.176\",\"ip_address0\":\"Turquoise\",\"ip_address1\":\"Euro\",\"ip_address2\":\"1qttm1nWiNDfpwuaYuoj7S7TXxUWxauBt\",\"ip_address3\":\"Demivee\",\"ip_address4\":false,\"ip_address5\":\"6/27/2015\"}"
		// it adds spaces
		let jsonResult = "{ \"id\" : 1, \"first_name\" : \"Kimberly\", \"last_name\" : \"Gonzales\", \"email\" : \"kgonzales0@usnews.com\", \"country\" : \"France\", \"ip_address\" : \"164.55.182.176\", \"ip_address0\" : \"Turquoise\", \"ip_address1\" : \"Euro\", \"ip_address2\" : \"1qttm1nWiNDfpwuaYuoj7S7TXxUWxauBt\", \"ip_address3\" : \"Demivee\", \"ip_address4\" : false, \"ip_address5\" : \"6\\/27\\/2015\" }"
		do {
			let bson = try BSON(json: json)
			defer {
				bson.close()
			}
			let backToJson = bson.description
			
			XCTAssert(jsonResult == backToJson, backToJson)
		} catch {
			XCTAssert(false, "Exception was thrown \(error)")
		}
    }
	
	func testBSONAppend() {
		let bson = BSON()
		defer {
			bson.close()
		}
		
		XCTAssert(bson.append("stringKey", string: "String Value"))
		XCTAssert(bson.append("intKey", int: 42))
		XCTAssert(bson.append("nullKey"))
		XCTAssert(bson.append("int32Key", int32: 42))
		XCTAssert(bson.append("doubleKey", double: 4.2))
		
		XCTAssert(bson.append("boolKey", bool: true))
		
		let t = Darwin.time(nil)
		XCTAssert(bson.append("timeKey", time: t))
		XCTAssert(bson.append("dateTimeKey", dateTime: 4200102))
		
		let str = bson.asString
		let expectedJson = "{ \"stringKey\" : \"String Value\", \"intKey\" : 42, \"nullKey\" : null, \"int32Key\" : 42, \"doubleKey\" : 4.2, " +
			"\"boolKey\" : true, \"timeKey\" : { \"$date\" : \(t * 1000) }, \"dateTimeKey\" : { \"$date\" : 4200102 } }"
		
		XCTAssert(str == expectedJson, "\n\(str)\n\(expectedJson)\n")
	}
	
	func testBSONHasFields() {
		let bson = BSON()
		defer {
			bson.close()
		}
		
		XCTAssert(bson.append("stringKey", string: "String Value"))
		XCTAssert(bson.append("intKey", int: 42))
		XCTAssert(bson.append("nullKey"))
		XCTAssert(bson.append("int32Key", int32: 42))
		XCTAssert(bson.append("doubleKey", double: 4.2))
		
		XCTAssert(bson.append("boolKey", bool: true))
		
		let t = Darwin.time(nil)
		XCTAssert(bson.append("timeKey", time: t))
		XCTAssert(bson.append("dateTimeKey", dateTime: 4200102))
		
		let str = bson.asString
		let expectedJson = "{ \"stringKey\" : \"String Value\", \"intKey\" : 42, \"nullKey\" : null, \"int32Key\" : 42, \"doubleKey\" : 4.2, " +
		"\"boolKey\" : true, \"timeKey\" : { \"$date\" : \(t * 1000) }, \"dateTimeKey\" : { \"$date\" : 4200102 } }"
		
		XCTAssert(str == expectedJson, "\n\(str)\n\(expectedJson)\n")
		
		XCTAssert(bson.countKeys() == 8)
		
		XCTAssert(bson.hasField("nullKey"))
		XCTAssert(bson.hasField("doubleKey"))
		XCTAssert(false == bson.hasField("noKey"))
	}
	
	func testBSONCompare() {
		let bson = BSON()
		defer {
			bson.close()
		}
		
		XCTAssert(bson.append("stringKey", string: "String Value"))
		
		let expectedJson = "{ \"stringKey\" : \"String Value\" }"
		
		let bson2 = try! BSON(json: expectedJson)
		
		let cmp = bson == bson2
		
		XCTAssert(cmp, "\n\(bson.asString)\n\(bson2.asString)\n")
	}
	
	func testClientConnect() {
		let client = MongoClient(uri: "mongodb://localhost")
		let status = client.serverStatus()
		switch status {
		case .Error(let domain, let code, let message):
			XCTAssert(false, "Error: \(domain) \(code) \(message)")
		case .ReplyDoc(let doc):
			print("Status doc: \(doc)")
			XCTAssert(true)
		default:
			XCTAssert(false, "Strange reply type \(status)")
		}
	}
	
	func testClientConnectFail() {
		let client = MongoClient(uri: "mongodb://typo")
		let status = client.serverStatus()
		switch status {
		case .Error(let domain, let code, let message):
			print("Error: \(domain) \(code) \(message)")
			XCTAssert(true, "Error: \(domain) \(code) \(message)")
		case .ReplyDoc(let doc):
			print("Status doc: \(doc)")
			XCTAssert(false)
		default:
			XCTAssert(false, "Strange reply type \(status)")
		}
	}
	
	func testClientGetDatabase() {
		let client = MongoClient(uri: "mongodb://localhost")
		let db = client.getDatabase("test")
		XCTAssert(db.name() == "test")
		db.close()
		client.close()
	}
	
	func testDBCreateCollection() {
		let client = MongoClient(uri: "mongodb://localhost")
		let db = client.getDatabase("test")
		XCTAssert(db.name() == "test")
		
		let oldC = db.getCollection("testcollection")
		oldC.drop()
		
		let result = db.createCollection("testcollection", options: BSON())
		switch result {
		case .ReplyCollection(let collection):
			XCTAssert(collection.name() == "testcollection")
			collection.close()
		default:
			XCTAssert(false, "Bad result \(result)")
		}
		db.close()
		client.close()
	}
	
	func testClientGetDatabaseNames() {
		let client = MongoClient(uri: "mongodb://localhost")
		let db = client.getDatabase("test")
		XCTAssert(db.name() == "test")
		
		let collection = db.getCollection("testcollection")
		XCTAssert(collection.name() == "testcollection")
			
		let bson = BSON()
		defer {
			bson.close()
		}
		
		XCTAssert(bson.append("stringKey", string: "String Value"))
		XCTAssert(bson.append("intKey", int: 42))
		XCTAssert(bson.append("nullKey"))
		XCTAssert(bson.append("int32Key", int32: 42))
		XCTAssert(bson.append("doubleKey", double: 4.2))
		XCTAssert(bson.append("boolKey", bool: true))
		
		let result2 = collection.save(bson)
		switch result2 {
		case .Success:
			XCTAssert(true)
		default:
			XCTAssert(false, "Bad result \(result2)")
		}
		
		collection.close()
	
		db.close()
		
		let names = client.databaseNames()
		
		XCTAssert(names == ["test"])
		
		client.close()
	}
	
	func testGetCollection() {
		let client = MongoClient(uri: "mongodb://localhost")
		let db = client.getDatabase("test")
		let col = db.getCollection("testcollection")
		XCTAssert(db.name() == "test")
		XCTAssert(col.name() == "testcollection")
		db.close()
		client.close()
	}
	
	func testDeleteDoc() {
		let client = MongoClient(uri: "mongodb://localhost")
		let db = client.getDatabase("test")
		XCTAssert(db.name() == "test")
		
		let collection = db.getCollection("testcollection")
		XCTAssert(collection.name() == "testcollection")
		
		let bson = BSON()
		defer {
			bson.close()
		}
		
		XCTAssert(bson.append("stringKey", string: "String Value"))
		XCTAssert(bson.append("intKey", int: 42))
		XCTAssert(bson.append("nullKey"))
		XCTAssert(bson.append("int32Key", int32: 42))
		XCTAssert(bson.append("doubleKey", double: 4.2))
		XCTAssert(bson.append("boolKey", bool: true))
		
		let result2 = collection.insert(bson)
		switch result2 {
		case .Success:
			XCTAssert(true)
		default:
			XCTAssert(false, "Bad result \(result2)")
		}
		
		let result3 = collection.remove(bson)
		switch result3 {
		case .Success:
			XCTAssert(true)
		default:
			XCTAssert(false, "Bad result \(result2)")
		}
		
	}
	
	
	
	
	
	
}











