//
//  PerfectLibTests.swift
//  PerfectLibTests
//
//  Created by Kyle Jessup on 2015-10-19.
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
@testable import PerfectLib

#if os(Linux)
import SwiftGlibc
import Foundation
#endif

class PerfectLibTests: XCTestCase {

	override func setUp() {
		super.setUp()
	#if os(Linux)
		SwiftGlibc.srand(UInt32(time(nil)))
	#endif
	}

	override func tearDown() {
		// Put teardown code here. This method is called after the invocation of each test method in the class.
		super.tearDown()
	}

	func testJSONConvertibleObject1() {

		class Test: JSONConvertibleObject {

			static let registerName = "test"

			var one = 0
			override func setJSONValues(_ values: [String : Any]) {
				self.one = getJSONValue(named: "One", from: values, defaultValue: 42)
			}
			override func getJSONValues() -> [String : Any] {
				return [JSONDecoding.objectIdentifierKey:Test.registerName, "One":1]
			}
		}

		JSONDecoding.registerJSONDecodable(name: Test.registerName, creator: { return Test() })

		do {
			let encoded = try Test().jsonEncodedString()
			let decoded = try encoded.jsonDecode() as? Test

			XCTAssert(decoded != nil)

			XCTAssert(decoded!.one == 1)
		} catch {
			XCTAssert(false, "Exception \(error)")
		}
	}
	
	func testJSONConvertibleObject2() {
		
		class User: JSONConvertibleObject {
			static let registerName = "user"
			var firstName = ""
			var lastName = ""
			var age = 0
			override func setJSONValues(_ values: [String : Any]) {
				self.firstName = getJSONValue(named: "firstName", from: values, defaultValue: "")
				self.lastName = getJSONValue(named: "lastName", from: values, defaultValue: "")
				self.age = getJSONValue(named: "age", from: values, defaultValue: 0)
			}
			override func getJSONValues() -> [String : Any] {
				return [
					JSONDecoding.objectIdentifierKey:User.registerName,
					"firstName":firstName,
					"lastName":lastName,
					"age":age
				]
			}
		}
		
		// register the class. do this once
		JSONDecoding.registerJSONDecodable(name: User.registerName, creator: { return User() })
		
		// encode and decode the object
		let user = User()
		user.firstName = "Donnie"
		user.lastName = "Darko"
		user.age = 17
		
		do {
			let encoded = try user.jsonEncodedString()
			print(encoded)
			
			guard let user2 = try encoded.jsonDecode() as? User else {
				return XCTAssert(false, "Invalid object \(encoded)")
			}
			
			XCTAssert(user.firstName == user2.firstName)
			XCTAssert(user.lastName == user2.lastName)
			XCTAssert(user.age == user2.age)
		} catch {}
	}

	func testJSONEncodeDecode() {

		let srcAry: [[String:Any]] = [["i": -41451, "i2": 41451, "d": -42E+2, "t": true, "f": false, "n": nil as String? as Any, "a":[1, 2, 3, 4]], ["another":"one"]]
		var encoded = ""
		var decoded: [Any]?
		do {

			encoded = try srcAry.jsonEncodedString()

		} catch let e {
			XCTAssert(false, "Exception while encoding JSON \(e)")
			return
		}

		do {

			decoded = try encoded.jsonDecode() as? [Any]

		} catch let e {
			XCTAssert(false, "Exception while decoding JSON \(e)")
			return
		}

		XCTAssert(decoded != nil)

		let resAry = decoded!

		XCTAssert(srcAry.count == resAry.count)

		for index in 0..<srcAry.count {

			let d1 = srcAry[index]
			let d2 = resAry[index] as? [String:Any]

			for (key, value) in d1 {

				let value2 = d2![key]

				XCTAssert(value2 != nil)

				switch value {
				case let i as Int:
					XCTAssert(i == value2 as! Int)
				case let d as Double:
					XCTAssert(d == value2 as! Double)
				case let s as String:
					XCTAssert(s == value2 as! String)
				case let s as Bool:
					XCTAssert(s == value2 as! Bool)

				default:
					()
					// does not go on to test sub-sub-elements
				}
			}

		}
	}
    func testIntegerTypesEncode(){
        let i8:Int8 = -12
        let i16:Int16 = -1234
        let i32:Int32 = -1234567890
        let i64:Int64 = -123456789012345678

        let u8:UInt8 = 12
        let u16:UInt16 = 1234
        let u32:UInt32 = 1234567890
        let u64:UInt64 = 123456789012345678
        
        var srcDict:[String:Any] = [String:Any]()
        var destDict:[String:Any]?
        
        srcDict["i8"] = i8
        srcDict["i16"] = i8
        srcDict["i32"] = i8
        srcDict["i64"] = i8
        srcDict["u8"] = i8
        srcDict["u16"] = i8
        srcDict["u32"] = i8
        srcDict["u64"] = i8
        
        
        var encoded = ""
        
        
        do {
            
            encoded = try i8.jsonEncodedString()
            XCTAssert(encoded == String(i8), "Invalid result")
            
        } catch let e {
            XCTAssert(false, "Exception while encoding i8 \(e)")
            return
        }

        do {
            
            encoded = try i16.jsonEncodedString()
            XCTAssert(encoded == String(i16), "Invalid result")

        } catch let e {
            XCTAssert(false, "Exception while encoding i16 \(e)")
            return
        }

        do {
            
            encoded = try i32.jsonEncodedString()
            XCTAssert(encoded == String(i32), "Invalid result")

        } catch let e {
            XCTAssert(false, "Exception while encoding i32 \(e)")
            return
        }

        do {
            
            encoded = try i64.jsonEncodedString()
            XCTAssert(encoded == String(i64), "Invalid result")

        } catch let e {
            XCTAssert(false, "Exception while encoding i64 \(e)")
            return
        }

        do {
            
            encoded = try u8.jsonEncodedString()
            XCTAssert(encoded == String(u8), "Invalid result")

        } catch let e {
            XCTAssert(false, "Exception while encoding u8 \(e)")
            return
        }
        
        do {
            
            encoded = try u16.jsonEncodedString()
            XCTAssert(encoded == String(u16), "Invalid result")

        } catch let e {
            XCTAssert(false, "Exception while encoding u16 \(e)")
            return
        }
        
        do {
            
            encoded = try u32.jsonEncodedString()
            XCTAssert(encoded == String(u32), "Invalid result")

        } catch let e {
            XCTAssert(false, "Exception while encoding u32 \(e)")
            return
        }
        
        do {
            
            encoded = try u64.jsonEncodedString()
            XCTAssert(encoded == String(u64), "Invalid result")

        } catch let e {
            XCTAssert(false, "Exception while encoding u64 \(e)")
            return
        }
        
        do {
            encoded = ""
            encoded = try srcDict.jsonEncodedString()
            XCTAssert(encoded != "", "Invalid result")
        } catch let e {
            XCTAssert(false, "Exception while encoding srcDict \(e)")
        }

        do {
            destDict = try encoded.jsonDecode() as? [String:Any]
            
        } catch let e {
            XCTAssert(false, "Exception while decoding into destDict \(e)" )
        }
        
        for (key, value) in destDict! {
            
            let value2 = srcDict[key]
            XCTAssert(value2 != nil)
            switch value2 {
            case let i as Int8:
                XCTAssert(value as! Int == Int(i))
            case let i as Int16:
                XCTAssert(value as! Int == Int(i))
            case let i as Int32:
                XCTAssert(value as! Int == Int(i))
            case let i as Int64:
                XCTAssert(value as! Int == Int(i))
            case let i as UInt8:
                XCTAssert(value as! Int == Int(i))
            case let i as UInt16:
                XCTAssert(value as! Int == Int(i))
            case let i as UInt32:
                XCTAssert(value as! Int == Int(i))
            case let i as UInt64:
                XCTAssert(value as! Int == Int(i))
            default:
                ()
            }
            
        }
    }
    
	func testJSONDecodeUnicode() {
		var decoded: [String: Any]?
		let jsonStr = "{\"emoji\": \"\\ud83d\\ude33\"}"     // {"emoji": "\ud83d\ude33"}
		do {
			decoded = try jsonStr.jsonDecode() as? [String: Any]
		} catch let e {

			XCTAssert(false, "Exception while decoding JSON \(e)")
			return
		}

		XCTAssert(decoded != nil)
		let value = decoded!["emoji"]
		XCTAssert(value != nil)
		let emojiStr = decoded!["emoji"] as! String
		XCTAssert(emojiStr == "😳")
	}

	func testSysProcess() {
		do {
			let proc = try SysProcess("ls", args:["-l", "/"], env:[("PATH", "/usr/bin:/bin")])

			XCTAssertTrue(proc.isOpen())
			XCTAssertNotNil(proc.stdin)

			let fileOut = proc.stdout!
			let data = try fileOut.readSomeBytes(count: 4096)

			XCTAssertTrue(data.count > 0)

			let waitRes = try proc.wait()

			XCTAssert(0 == waitRes, "\(waitRes) \(UTF8Encoding.encode(bytes: data))")

			proc.close()
		} catch {
			XCTAssert(false, "Exception running SysProcess test: \(error)")
		}
	}
	
	func testSysProcessGroup() {
		do {
			let proc = try SysProcess("sh", args: ["-c", "(sleep 10s &) ; (sleep 10s &) ; sleep 10s"], env: [("PATH", "/usr/bin:/bin")], newGroup: true)
			
			XCTAssert(proc.isOpen())
			XCTAssertNotEqual(-1, proc.pid)
			XCTAssertNotEqual(-1, proc.gid)
			
			// Ensure that the process group is different from the test process
			#if os(Linux)
				let testGid = SwiftGlibc.getpgrp()
			#else
				let testGid = Darwin.getpgrp()
			#endif
			XCTAssertNotEqual(testGid, proc.gid)
			
			let savedGid = proc.gid
			
			XCTAssertTrue(try hasChildProcesses(gid: savedGid))
			_ = try proc.killGroup()
			XCTAssertFalse(try hasChildProcesses(gid: savedGid))
		} catch {
			XCTAssert(false, "Exception running SysProcess group test: \(error)")
		}
	}
	
	private func hasChildProcesses(gid: pid_t) throws -> Bool {
		let proc = try SysProcess("sh", args: ["-c", "ps -e -o pgid,comm | grep \(gid)"], env: [("PATH", "/usr/bin:/bin")])
		
		_ = try proc.wait()
		
		if let bytes = try proc.stdout?.readSomeBytes(count: 4096) {
			return bytes.count > 0
		} else {
			return false
		}
	}

	func testStringByEncodingHTML() {
		let src = "<b>\"quoted\" '& ☃"
		let res = src.stringByEncodingHTML
		XCTAssertEqual(res, "&lt;b&gt;&quot;quoted&quot; &#39;&amp; &#9731;")
	}

	func testStringByEncodingURL() {
		let src = "This has \"weird\" characters & ßtuff"
		let res = src.stringByEncodingURL
		XCTAssertEqual(res, "This%20has%20%22weird%22%20characters%20&%20%C3%9Ftuff")
	}

	func testStringByDecodingURL() {
		let src = "This has \"weird\" characters & ßtuff"
		let mid = src.stringByEncodingURL
		guard let res = mid.stringByDecodingURL else {
			XCTAssert(false, "Got nil String")
			return
		}
		XCTAssert(res == src, "Bad URL decoding")
	}

	func testStringByDecodingURL2() {
		let src = "This is badly%PWencoded"
		let res = src.stringByDecodingURL

		XCTAssert(res == nil, "Bad URL decoding")
	}

	func testStringByReplacingString() {

		let src = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ"
		let test = "ABCFEDGHIJKLMNOPQRSTUVWXYZABCFEDGHIJKLMNOPQRSTUVWXYZABCFEDGHIJKLMNOPQRSTUVWXYZ"
		let find = "DEF"
		let rep = "FED"

		let res = src.stringByReplacing(string: find, withString: rep)

		XCTAssert(res == test)
	}

	func testStringByReplacingString2() {

		let src = ""
		let find = "DEF"
		let rep = "FED"

		let res = src.stringByReplacing(string: find, withString: rep)

		XCTAssert(res == src)
	}

	func testStringByReplacingString3() {

		let src = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ"
		let find = ""
		let rep = "FED"

		let res = src.stringByReplacing(string: find, withString: rep)

		XCTAssert(res == src)
	}

	func testStringBeginsWith() {
		let a = "123456"

		XCTAssert(a.begins(with: "123"))
		XCTAssert(!a.begins(with: "abc"))
	}

	func testStringEndsWith() {
		let a = "123456"

		XCTAssert(a.ends(with: "456"))
		XCTAssert(!a.ends(with: "abc"))
	}

	func testDeletingPathExtension() {
		let path = "/a/b/c.txt"
		let del = path.deletingFileExtension
		XCTAssert("/a/b/c" == del)
	}

	func testGetPathExtension() {
		let path = "/a/b/c.txt"
		let ext = path.filePathExtension
		XCTAssert("txt" == ext)
	}

	func testDirCreate() {
		let path = "/tmp/a/b/c/d/e/f/g"
		do {
			try Dir(path).create()

			XCTAssert(Dir(path).exists)

			var unPath = path

			while unPath != "/tmp" {
				try Dir(unPath).delete()
				unPath = unPath.deletingLastFilePathComponent
			}
		} catch {
			XCTAssert(false, "Error while creating dirs: \(error)")
		}
	}

	func testDirCreateRel() {
		let path = "a/b/c/d/e/f/g"
		do {
			try Dir(path).create()
			XCTAssert(Dir(path).exists)
			var unPath = path
			repeat {
				try Dir(unPath).delete()

								// this was killing linux on the final path component
								//unPath = unPath.stringByDeletingLastPathComponent

								var splt = unPath.split(separator: "/").map(String.init)
								splt.removeLast()
								unPath = splt.joined(separator: "/")

			} while !unPath.isEmpty
		} catch {
			XCTAssert(false, "Error while creating dirs: \(error)")
		}
	}

	func testDirForEach() {
		let dirs = ["a/", "b/", "c/"]
		do {
			try Dir("/tmp/a").create()
			for d in dirs {
				try Dir("/tmp/a/\(d)").create()
			}
			var ta = [String]()
			try Dir("/tmp/a").forEachEntry {
				name in
				ta.append(name)
			}
						ta.sort()
			XCTAssert(ta == dirs, "\(ta) == \(dirs)")
			for d in dirs {
				try Dir("/tmp/a/\(d)").delete()
			}
			try Dir("/tmp/a").delete()
		} catch {
			XCTAssert(false, "Error while creating dirs: \(error)")
		}
	}
	
	func testFilePerms() {
		let fileName = "/tmp/\(UUID().uuidString)"
		let file = File(fileName)
		do {
			try file.open(.readWrite, permissions: [.readUser, .writeUser])
			defer {
				file.delete()
			}
			
			let res = file.perms.contains([.readUser, .writeUser])
			XCTAssert(res, "\(file.perms) != \([File.PermissionMode.readUser, File.PermissionMode.writeUser])")
			
		} catch {
			XCTAssert(false, "Error testing file perms: \(error)")
		}
	}
	
	func testDirPerms() {
		let fileName = "/tmp/\(UUID().uuidString)"
		let file = Dir(fileName)
		do {
			try file.create(perms: [.readUser, .writeUser])
			
			let res = file.perms.contains([.readUser, .writeUser])
			XCTAssert(res, "\(file.perms) != \([File.PermissionMode.readUser, File.PermissionMode.writeUser])")
			
			try file.delete()
		} catch {
			XCTAssert(false, "Error testing file perms: \(error)")
		}
	}
	
	func testBytesIO() {
		let i8 = 254 as UInt8
		let i16 = 54045 as UInt16
		let i32 = 4160745471 as UInt32
		let i64 = 17293541094125989887 as UInt64
		
		let bytes = Bytes()
		
		bytes.import64Bits(from: i64)
			.import32Bits(from: i32)
			.import16Bits(from: i16)
			.import8Bits(from: i8)
		
		let bytes2 = Bytes()
		bytes2.importBytes(from: bytes)
		
		XCTAssert(i64 == bytes2.export64Bits())
		XCTAssert(i32 == bytes2.export32Bits())
		XCTAssert(i16 == bytes2.export16Bits())
		bytes2.position -= MemoryLayout<UInt16>.size
		XCTAssert(i16 == bytes2.export16Bits())
		XCTAssert(bytes2.availableExportBytes == 1)
		XCTAssert(i8 == bytes2.export8Bits())
	}
	
	func testSymlink() {
		let f1 = File("./foo")
		let f2 = File("./foo2")
		do {
			f2.delete()
			try f1.open(.truncate)
			try f1.write(string: "test")
			f1.close()
			defer {
				f1.delete()
				f2.delete()
			}
			
			let newF2 = try f1.linkTo(path: f2.path)
			
			XCTAssert(try newF2.readString() == "test")
			XCTAssert(newF2.isLink)
		} catch {
			XCTAssert(false, "\(error)")
		}
	}

	func testEnvironments() {
		XCTAssertTrue(Env.set("foo", value: "bar"))
		XCTAssertTrue(Env.set("koo", value: "kar"))
		XCTAssertEqual(Env.get("foo"), "bar")
		XCTAssertEqual(Env.get("koo"), "kar")
		XCTAssertTrue(Env.del("foo"))
		XCTAssertTrue(Env.del("koo"))
		XCTAssertNil(Env.get("foo"))
		XCTAssertNil(Env.get("koo"))
		let before = Env.get()
		let empty = Env.set(["foo":"bar", "koo":"kar"])
		let after = Env.get()
		XCTAssertTrue(empty.isEmpty)
		XCTAssertNil(before["foo"])
		XCTAssertNil(before["koo"])
		XCTAssertEqual(after["foo"], "bar")
		XCTAssertEqual(after["koo"], "kar")
	}
}

extension PerfectLibTests {
	static var allTests : [(String, (PerfectLibTests) -> () throws -> Void)] {
		return [
			("testJSONConvertibleObject1", testJSONConvertibleObject1),
			("testJSONConvertibleObject2", testJSONConvertibleObject2),
			("testJSONEncodeDecode", testJSONEncodeDecode),
			("testJSONDecodeUnicode", testJSONDecodeUnicode),
			("testSysProcess", testSysProcess),
			("testSysProcessGroup", testSysProcessGroup),
			("testStringByEncodingHTML", testStringByEncodingHTML),
			("testStringByEncodingURL", testStringByEncodingURL),
			("testStringByDecodingURL", testStringByDecodingURL),
			("testStringByDecodingURL2", testStringByDecodingURL2),
			("testStringByReplacingString", testStringByReplacingString),
			("testStringByReplacingString2", testStringByReplacingString2),
			("testStringByReplacingString3", testStringByReplacingString3),

			("testDeletingPathExtension", testDeletingPathExtension),
			("testGetPathExtension", testGetPathExtension),

			("testDirCreate", testDirCreate),
			("testDirCreateRel", testDirCreateRel),
			("testDirForEach", testDirForEach),
			
			("testFilePerms", testFilePerms),
			("testDirPerms", testDirPerms),
      		("testEnvironments", testEnvironments),

			("testBytesIO", testBytesIO),
            ("testIntegerTypesEncode", testIntegerTypesEncode)
		]
	}
}
