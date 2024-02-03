//
//  SQLiteTests.swift
//  PerfectSQLite
//
//  Created by Kyle Jessup on 2016-04-09.
//  Copyright © 2016 PerfectlySoft. All rights reserved.
//
// ===----------------------------------------------------------------------===//
//
// This source file is part of the Perfect.org open source project
//
// Copyright (c) 2015 - 2016 PerfectlySoft Inc. and the Perfect project authors
// Licensed under Apache License v2.0
//
// See http://perfect.org/licensing.html for license information
//
// ===----------------------------------------------------------------------===//
//

import Foundation
import XCTest
import PerfectCRUD
@testable import PerfectSQLite

let testDBRowCount = 5
let testDBName = "/tmp/crud_test.db"
typealias DBConfiguration = SQLiteDatabaseConfiguration
func getDB(reset: Bool = true) throws -> Database<DBConfiguration> {
	if reset {
		unlink(testDBName)
	}
	return Database(configuration: try DBConfiguration(testDBName))
}
// swiftlint:disable type_body_length type_name
class PerfectSQLiteTests: XCTestCase {
	// copy + paste from here into other CRUD driver projects
	struct TestTable1: Codable, TableNameProvider {
		enum CodingKeys: String, CodingKey {
			case id, name, integer = "int", double = "doub", blob, subTables
		}
		static let tableName = "test_table_1"

		@PrimaryKey var id: Int
		let name: String?
		let integer: Int?
		let double: Double?
		let blob: [UInt8]?
		let subTables: [TestTable2]?
		init(id: Int,
			 name: String? = nil,
			 integer: Int? = nil,
			 double: Double? = nil,
			 blob: [UInt8]? = nil,
			 subTables: [TestTable2]? = nil) {
			self.id = id
			self.name = name
			self.integer = integer
			self.double = double
			self.blob = blob
			self.subTables = subTables
		}
	}

	struct TestTable2: Codable {
		@PrimaryKey var id: UUID
		@ForeignKey(TestTable1.self, onDelete: cascade, onUpdate: cascade) var parentId: Int
		let date: Date
		let name: String?
		let int: Int?
		let doub: Double?
		let blob: [UInt8]?
		init(id: UUID,
			 parentId: Int,
			 date: Date,
			 name: String? = nil,
			 int: Int? = nil,
			 doub: Double? = nil,
			 blob: [UInt8]? = nil) {
			self.id = id
			self.date = date
			self.name = name
			self.int = int
			self.doub = doub
			self.blob = blob
			self.parentId = parentId
		}
	}

	override func setUp() {
		super.setUp()
		CRUDClearTableStructureCache()
	}
	override func tearDown() {
		CRUDLogging.flush()
		super.tearDown()
	}

	func testScratch1() {
//		@propertyWrapper
//		struct Default<Value: Codable>: Codable {
//			var wrappedValue: Value
//			init(wrappedValue: Value) {
//				self.wrappedValue = wrappedValue
//			}
//		}

		struct Foo: Codable {
			@PrimaryKey var id: UUID
			var bars: [Bar]?
		}

		struct Bar: Codable {
			@PrimaryKey var id: UUID
			@ForeignKey(Foo.self, onDelete: cascade, onUpdate: cascade)
			var fooId: UUID

			init(id: UUID, fooId: UUID) {
				self.id = id
				self.fooId = fooId
			}
		}

		let id = UUID()
		_ = Foo(id: id)
		_ = Bar(id: UUID(), fooId: id)
		do {
			let db = try getDB()
			try db.create(Foo.self, policy: .dropTable)
		} catch {
			XCTFail("\(error)")
		}
	}

	func testCreate1() {
		do {
			let db = try getDB()
			try db.create(TestTable1.self, policy: .dropTable)
			do {
				let t2 = db.table(TestTable2.self)
				try t2.index(\.parentId)
			}
			let t1 = db.table(TestTable1.self)
			let t2 = db.table(TestTable2.self)
			let subId = UUID()
			try db.transaction {
				let newOne = TestTable1(id: 2000, name: "New One", integer: 40)
				try t1.insert(newOne)
				let newSub1 = TestTable2(id: subId, parentId: 2000, date: Date(), name: "Me")
				let newSub2 = TestTable2(id: UUID(), parentId: 2000, date: Date(), name: "Not Me")
				try t2.insert([newSub1, newSub2])
			}
			let j21 = try t1.join(\.subTables, on: \.id, equals: \.parentId)
			let j2 = j21.where(\TestTable1.id == 2000 && \TestTable2.name == "Me")
			let j3 = j21.where(\TestTable1.id > 20 &&
							!(\TestTable1.name == "Me" || \TestTable1.name == "You"))
			XCTAssertEqual(try j3.count(), 1)
			try db.transaction {
				let j2a = try j2.select().map { $0 }
				XCTAssertEqual(try j2.count(), 1)
				XCTAssertEqual(j2a.count, 1)
				guard j2a.count == 1 else {
					return
				}
				let obj = j2a[0]
				XCTAssertEqual(obj.id, 2000)
				XCTAssertNotNil(obj.subTables)
				let subTables = obj.subTables!
				XCTAssertEqual(subTables.count, 1)
				let obj2 = subTables[0]
				XCTAssertEqual(obj2.id, subId)
			}
			try db.create(TestTable1.self)
			do {
				let j2a = try j2.select().map { $0 }
				XCTAssertEqual(try j2.count(), 1)
				XCTAssertEqual(j2a[0].id, 2000)
			}
			try db.create(TestTable1.self, policy: .dropTable)
			do {
				let j2b = try j2.select().map { $0 }
				XCTAssertEqual(j2b.count, 0)
			}
		} catch {
			XCTFail("\(error)")
		}
	}

	func testCreate2() {
		do {
			let db = try getTestDB()
			try db.create(TestTable1.self, policy: .dropTable)
			do {
				let t2 = db.table(TestTable2.self)
				try t2.index(\.parentId, \.date)
			}
			let t1 = db.table(TestTable1.self)
			do {
				let newOne = TestTable1(id: 2000, name: "New One", integer: 40)
				try t1.insert(newOne)
			}
			let j2 = try t1.where(\TestTable1.id == 2000).select()
			do {
				let j2a = j2.map { $0 }
				XCTAssertEqual(j2a.count, 1)
				XCTAssertEqual(j2a[0].id, 2000)
			}
			try db.create(TestTable1.self)
			do {
				let j2a = j2.map { $0 }
				XCTAssertEqual(j2a.count, 1)
				XCTAssertEqual(j2a[0].id, 2000)
			}
			try db.create(TestTable1.self, policy: .dropTable)
			do {
				let j2b = j2.map { $0 }
				XCTAssertEqual(j2b.count, 0)
			}
		} catch {
			XCTFail("\(error)")
		}
	}

	func testCreate3() {
		struct FakeTestTable1: Codable, TableNameProvider {
			enum CodingKeys: String, CodingKey {
				case id, name, double = "doub", double2 = "doub2", blob, subTables
			}
			static let tableName = "test_table_1"
			let id: Int
			let name: String?
			let double2: Double?
			let double: Double?
			let blob: [UInt8]?
			let subTables: [TestTable2]?
		}
		do {
			let db = try getTestDB()
			try db.create(TestTable1.self, policy: [.dropTable, .shallow])

			do {
				let t1 = db.table(TestTable1.self)
				let newOne = TestTable1(id: 2000, name: "New One", integer: 40)
				try t1.insert(newOne)
			}
			do {
				try db.create(FakeTestTable1.self, policy: [.reconcileTable, .shallow])
				let t1 = db.table(FakeTestTable1.self)
				let j2 = try t1.where(\FakeTestTable1.id == 2000).select()
				do {
					let j2a = j2.map { $0 }
					XCTAssertEqual(j2a.count, 1)
					XCTAssertEqual(j2a[0].id, 2000)
				}
			}
		} catch {
			XCTFail("\(error)")
		}
	}

	func getTestDB() throws -> Database<DBConfiguration> {
		do {
			let db = try getDB()
			try db.create(TestTable1.self, policy: .dropTable)
			try db.transaction {
				() -> () in
				try db.table(TestTable1.self)
					.insert((1...testDBRowCount).map { num -> TestTable1 in
						let n = UInt8(num)
						let blob: [UInt8]? = (num % 2 != 0) ? nil : [UInt8](arrayLiteral: n+1, n+2, n+3, n+4, n+5)
						return TestTable1(id: num,
							name: "This is name bind \(num)",
							integer: num,
							double: Double(num),
							blob: blob)
					})
			}
			try db.transaction {
				() -> () in
				try db.table(TestTable2.self)
					.insert((1...testDBRowCount).flatMap { parentId -> [TestTable2] in
						return (1...testDBRowCount).map { num -> TestTable2 in
							let n = UInt8(num)
							let blob: [UInt8]? = [UInt8](arrayLiteral: n+1, n+2, n+3, n+4, n+5)
							return TestTable2(id: UUID(),
											  parentId: parentId,
											  date: Date(),
											  name: num % 2 == 0 ? "This is name bind \(num)" : "me",
											  int: num,
											  doub: Double(num),
											  blob: blob)
						}
					})
			}
		} catch {
			XCTFail("\(error)")
		}
		return try getDB(reset: false)
	}

	func testSelectAll() {
		do {
			let db = try getTestDB()
			let j2 = db.table(TestTable1.self)
			for row in try j2.select() {
				XCTAssertNil(row.subTables)
			}
		} catch {
			XCTFail("\(error)")
		}
	}

	func testSelectIn() {
		do {
			let db = try getTestDB()
			let table = db.table(TestTable1.self)
			XCTAssertEqual(2, try table.where(\TestTable1.id ~ [2, 4]).count())
			XCTAssertEqual(3, try table.where(\TestTable1.id !~ [2, 4]).count())
		} catch {
			XCTFail("\(error)")
		}
	}

	func testSelectLikeString() {
		do {
			let db = try getTestDB()
			let table = db.table(TestTable2.self)
			XCTAssertEqual(25, try table.where(\TestTable2.name %=% "me").count())
			XCTAssertEqual(15, try table.where(\TestTable2.name =% "me").count())
			XCTAssertEqual(15, try table.where(\TestTable2.name %= "me").count())
			XCTAssertEqual( 0, try table.where(\TestTable2.name %!=% "me").count())
			XCTAssertEqual(10, try table.where(\TestTable2.name !=% "me").count())
			XCTAssertEqual(10, try table.where(\TestTable2.name %!= "me").count())
		} catch {
			XCTFail("\(error)")
		}
	}

	func testSelectJoin() {
		do {
			let db = try getTestDB()
			let j2 = try db.table(TestTable1.self)
				.order(by: \TestTable1.name)
				.join(\.subTables, on: \.id, equals: \.parentId)
				.order(by: \.id)
				.where(\TestTable2.name == "me")

			let j2c = try j2.count()
			let j2a = try j2.select().map {$0}
			let j2ac = j2a.count
			XCTAssertNotEqual(j2c, 0)
			XCTAssertEqual(j2c, j2ac)
			j2a.forEach { row in
				XCTAssertFalse(row.subTables?.isEmpty ?? true)
			}
		} catch {
			XCTFail("\(error)")
		}
	}

	func testInsert1() {
		do {
			let db = try getTestDB()
			let t1 = db.table(TestTable1.self)
			let newOne = TestTable1(id: 2000, name: "New One", integer: 40)
			try t1.insert(newOne)
			let j1 = t1.where(\TestTable1.id == newOne.id)
			let j2 = try j1.select().map {$0}
			XCTAssertEqual(try j1.count(), 1)
			XCTAssertEqual(j2[0].id, 2000)
		} catch {
			XCTFail("\(error)")
		}
	}

	func testInsert2() {
		do {
			let db = try getTestDB()
			let t1 = db.table(TestTable1.self)
			let newOne = TestTable1(id: 2000, name: "New One", integer: 40)
			try t1.insert(newOne, ignoreKeys: \TestTable1.integer)
			let j1 = t1.where(\TestTable1.id == newOne.id)
			let j2 = try j1.select().map {$0}
			XCTAssertEqual(try j1.count(), 1)
			XCTAssertEqual(j2[0].id, 2000)
			XCTAssertNil(j2[0].integer)
		} catch {
			XCTFail("\(error)")
		}
	}

	func testInsert3() {
		do {
			let db = try getTestDB()
			let t1 = db.table(TestTable1.self)
			let newOne = TestTable1(id: 2000, name: "New One", integer: 40)
			let newTwo = TestTable1(id: 2001, name: "New One", integer: 40)
			try t1.insert([newOne, newTwo], setKeys: \TestTable1.id, \TestTable1.integer)
			let j1 = t1.where(\TestTable1.id == newOne.id)
			let j2 = try j1.select().map {$0}
			XCTAssertEqual(try j1.count(), 1)
			XCTAssertEqual(j2[0].id, 2000)
			XCTAssertEqual(j2[0].integer, 40)
			XCTAssertNil(j2[0].name)
		} catch {
			XCTFail("\(error)")
		}
	}

	func testUpdate() {
		do {
			let db = try getTestDB()
			let newOne = TestTable1(id: 2000, name: "New One", integer: 40)
			let newId: Int = try db.transaction {
				try db.table(TestTable1.self).insert(newOne)
				let newOne2 = TestTable1(id: 2000, name: "New👻One Updated", integer: 41)
				try db.table(TestTable1.self)
					.where(\TestTable1.id == newOne.id)
					.update(newOne2, setKeys: \.name)
				return newOne2.id
			}
			let j2 = try db.table(TestTable1.self)
				.where(\TestTable1.id == newId)
				.select().map { $0 }
			XCTAssertEqual(1, j2.count)
			XCTAssertEqual(2000, j2[0].id)
			XCTAssertEqual("New👻One Updated", j2[0].name)
			XCTAssertEqual(40, j2[0].integer)
		} catch {
			XCTFail("\(error)")
		}
	}

	func testDelete() {
		do {
			let db = try getTestDB()
			let t1 = db.table(TestTable1.self)
			let newOne = TestTable1(id: 2000, name: "New One", integer: 40)
			try t1.insert(newOne)
			let query = t1.where(\TestTable1.id == newOne.id)
			let j1 = try query.select().map { $0 }
			XCTAssertEqual(j1.count, 1)
			try query.delete()
			let j2 = try query.select().map { $0 }
			XCTAssertEqual(j2.count, 0)
		} catch {
			XCTFail("\(error)")
		}
	}

	func testSelectLimit() {
		do {
			let db = try getTestDB()
			let j2 = db.table(TestTable1.self).limit(3, skip: 2)
			XCTAssertEqual(try j2.count(), 3)
		} catch {
			XCTFail("\(error)")
		}
	}

	func testSelectLimitWhere() {
		do {
			let db = try getTestDB()
			let j2 = db.table(TestTable1.self).limit(3).where(\TestTable1.id > 3)
			XCTAssertEqual(try j2.count(), 2)
			XCTAssertEqual(try j2.select().map {$0}.count, 2)
		} catch {
			XCTFail("\(error)")
		}
	}

	func testSelectOrderLimitWhere() {
		do {
			let db = try getTestDB()
			let j2 = db.table(TestTable1.self).order(by: \TestTable1.id).limit(3).where(\TestTable1.id > 3)
			XCTAssertEqual(try j2.count(), 2)
			XCTAssertEqual(try j2.select().map {$0}.count, 2)
		} catch {
			XCTFail("\(error)")
		}
	}

	func testSelectWhereNULL() {
		do {
			let db = try getTestDB()
			let t1 = db.table(TestTable1.self)
			let j1 = t1.where(\TestTable1.blob == nil)
			XCTAssert(try j1.count() > 0)
			let j2 = t1.where(\TestTable1.blob != nil)
			XCTAssert(try j2.count() > 0)
			CRUDLogging.flush()
		} catch {
			XCTFail("\(error)")
		}
	}

	// this is the general-overview example used in the readme
	func testPersonThing() {
		do {
			// CRUD can work with most Codable types.
			struct PhoneNumber: Codable {
				let personId: UUID
				let planetCode: Int
				let number: String
			}
			struct Person: Codable {
				let id: UUID
				let firstName: String
				let lastName: String
				let phoneNumbers: [PhoneNumber]?
			}

			// CRUD usage begins by creating a database connection.
			// The inputs for connecting to a database will differ depending on your client library.
			// Create a `Database` object by providing a configuration.
			// These examples will use SQLite for demonstration purposes,
			// 	but all code would be identical regardless of the datasource type.
			let db = Database(configuration: try SQLiteDatabaseConfiguration(testDBName))

			// Create the table if it hasn't been done already.
			// Table creates are recursive by default, so "PhoneNumber" is also created here.
			try db.create(Person.self, policy: .reconcileTable)

			// Get a reference to the tables we will be inserting data into.
			let personTable = db.table(Person.self)
			let numbersTable = db.table(PhoneNumber.self)

			// Add an index for personId, if it does not already exist.
			try numbersTable.index(\.personId)

			// Insert some sample data.
			do {
				// Insert some sample data.
				let owen = Person(id: UUID(), firstName: "Owen", lastName: "Lars", phoneNumbers: nil)
				let beru = Person(id: UUID(), firstName: "Beru", lastName: "Lars", phoneNumbers: nil)

				// Insert the people
				try personTable.insert([owen, beru])

				// Give them some phone numbers
				try numbersTable.insert([
					PhoneNumber(personId: owen.id, planetCode: 12, number: "555-555-1212"),
					PhoneNumber(personId: owen.id, planetCode: 15, number: "555-555-2222"),
					PhoneNumber(personId: beru.id, planetCode: 12, number: "555-555-1212")])
			}

			// Perform a query.
			// Let's find all people with the last name of Lars which have a phone number on planet 12.
			let query = try personTable
					.order(by: \.lastName, \.firstName)
				.join(\.phoneNumbers, on: \.id, equals: \.personId)
					.order(descending: \.planetCode)
				.where(\Person.lastName == "Lars" && \PhoneNumber.planetCode == 12)
				.select()

			// Loop through the results and print the names.
			for user in query {
				// We joined PhoneNumbers, so we should have values here.
				guard let numbers = user.phoneNumbers else {
					continue
				}
				for number in numbers {
					print(number.number)
				}
			}
			CRUDLogging.flush()
		} catch {
			XCTFail("\(error)")
		}
	}

	func testStandardJoin() {
		do {
			let db = try getTestDB()
			struct Parent: Codable {
				let id: Int
				let children: [Child]?
				init(id i: Int) {
					id = i
					children = nil
				}
			}
			struct Child: Codable {
				let id: Int
				let parentId: Int
			}
			try db.transaction {
				try db.create(Parent.self, policy: [.shallow, .dropTable]).insert(
					Parent(id: 1))
				try db.create(Child.self, policy: [.shallow, .dropTable]).insert(
					[Child(id: 1, parentId: 1),
					 Child(id: 2, parentId: 1),
					 Child(id: 3, parentId: 1)])
			}
			let join = try db.table(Parent.self)
				.join(\.children,
					  on: \.id,
					  equals: \.parentId)
				.where(\Parent.id == 1)

			guard let parent = try join.first() else {
				return XCTFail("Failed to find parent id: 1")
			}
			guard let children = parent.children else {
				return XCTFail("Parent had no children")
			}
			XCTAssertEqual(3, children.count)
			for child in children {
				XCTAssertEqual(child.parentId, parent.id)
			}
			CRUDLogging.flush()
		} catch {
			XCTFail("\(error)")
		}
	}

	func testJunctionJoin() {
		do {
			struct Student: Codable {
				let id: Int
				let classes: [Class]?
				init(id i: Int) {
					id = i
					classes = nil
				}
			}
			struct Class: Codable {
				let id: Int
				let students: [Student]?
				init(id i: Int) {
					id = i
					students = nil
				}
			}
			struct StudentClasses: Codable {
				let studentId: Int
				let classId: Int
			}
			let db = try getTestDB()
			try db.transaction {
				try db.create(Student.self, policy: [.dropTable, .shallow]).insert(
					Student(id: 1))
				try db.create(Class.self, policy: [.dropTable, .shallow]).insert([
					Class(id: 1),
					Class(id: 2),
					Class(id: 3)])
				try db.create(StudentClasses.self, policy: [.dropTable, .shallow]).insert([
					StudentClasses(studentId: 1, classId: 1),
					StudentClasses(studentId: 1, classId: 2),
					StudentClasses(studentId: 1, classId: 3)])
			}
			let join = try db.table(Student.self)
				.join(\.classes,
					  with: StudentClasses.self,
					  on: \.id,
					  equals: \.studentId,
					  and: \.id,
					  is: \.classId)
				.where(\Student.id == 1)
			guard let student = try join.first() else {
				return XCTFail("Failed to find student id: 1")
			}
			guard let classes = student.classes else {
				return XCTFail("Student had no classes")
			}
			XCTAssertEqual(3, classes.count)
			for aClass in classes {
				let join = try db.table(Class.self)
					.join(\.students,
						  with: StudentClasses.self,
						  on: \.id,
						  equals: \.classId,
						  and: \.id,
						  is: \.studentId)
					.where(\Class.id == aClass.id)
				guard let found = try join.first() else {
					XCTFail("Class with no students")
					continue
				}
				guard nil != found.students?.first(where: { $0.id == student.id }) else {
					XCTFail("Student not found in class")
					continue
				}
			}
			CRUDLogging.flush()
		} catch {
			XCTFail("\(error)")
		}
	}

	func testSelfJoin() {
		do {
			struct Me: Codable {
				let id: Int
				let parentId: Int
				let mes: [Me]?
				init(id i: Int, parentId p: Int) {
					id = i
					parentId = p
					mes = nil
				}
			}
			let db = try getTestDB()
			try db.transaction {
				() -> () in
				try db.create(Me.self, policy: .dropTable).insert([
					Me(id: 1, parentId: 0),
					Me(id: 2, parentId: 1),
					Me(id: 3, parentId: 1),
					Me(id: 4, parentId: 1),
					Me(id: 5, parentId: 1)
				])
			}
			let join = try db.table(Me.self)
				.join(\.mes, on: \.id, equals: \.parentId)
				.where(\Me.id == 1)
			guard let me = try join.first() else {
				return XCTFail("Unable to find me.")
			}
			guard let mes = me.mes else {
				return XCTFail("Unable to find meesa.")
			}
			XCTAssertEqual(mes.count, 4)
		} catch {
			XCTFail("\(error)")
		}
	}

	func testSelfJunctionJoin() {
		do {
			struct Me: Codable {
				let id: Int
				let us: [Me]?
				init(id i: Int) {
					id = i
					us = nil
				}
			}
			struct Us: Codable {
				let you: Int
				let them: Int
			}
			let db = try getTestDB()
			try db.transaction {
				() -> () in
				try db.create(Me.self, policy: .dropTable)
					.insert((1...5).map { .init(id: $0) })
				try db.create(Us.self, policy: .dropTable)
					.insert((2...5).map { .init(you: 1, them: $0) })
			}
			let join = try db.table(Me.self)
				.join(\.us,
					  with: Us.self,
					  on: \.id,
					  equals: \.you,
					  and: \.id,
					  is: \.them)
				.where(\Me.id == 1)
			guard let me = try join.first() else {
				return XCTFail("Unable to find me.")
			}
			guard let us = me.us else {
				return XCTFail("Unable to find us.")
			}
			XCTAssertEqual(us.count, 4)
		} catch {
			XCTFail("\(error)")
		}
	}

	func testCodableProperty() {
		do {
			struct Sub: Codable {
				let id: Int
			}
			struct Top: Codable {
				let id: Int
				let sub: Sub?
			}
			let db = try getTestDB()
			try db.create(Sub.self)
			try db.create(Top.self)
			let t1 = Top(id: 1, sub: Sub(id: 1))
			try db.table(Top.self).insert(t1)
			guard let top = try db.table(Top.self).where(\Top.id == 1).first() else {
				return XCTFail("Unable to find top.")
			}
			XCTAssertEqual(top.sub?.id, t1.sub?.id)
		} catch {
			XCTFail("\(error)")
		}
	}

	func testBadDecoding() {
		do {
			struct Top: Codable, TableNameProvider {
				static var tableName = "Top"
				let id: Int
			}
			struct NTop: Codable, TableNameProvider {
				static var tableName = "Top"
				let nid: Int
			}
			let db = try getTestDB()
			try db.create(Top.self, policy: .dropTable)
			let t1 = Top(id: 1)
			try db.table(Top.self).insert(t1)
			_ = try db.table(NTop.self).first()
			XCTFail("Should not have a valid object.")
		} catch {}
	}

	func testAllPrimTypes1() {
		struct AllTypes: Codable {
			let int: Int
			let uint: UInt
			let int64: Int64
			let uint64: UInt64
			let int32: Int32?
			let uint32: UInt32?
			let int16: Int16
			let uint16: UInt16
			let int8: Int8?
			let uint8: UInt8?
			let double: Double
			let float: Float
			let string: String
			let bytes: [Int8]
			let ubytes: [UInt8]?
			let b: Bool
		}
		do {
			let db = try getTestDB()
			try db.create(AllTypes.self, policy: .dropTable)
			let model = AllTypes(int: 1, uint: 2, int64: 3, uint64: 4, int32: 5, uint32: 6, int16: 7, uint16: 8, int8: 9, uint8: 10, double: 11, float: 12, string: "13", bytes: [1, 4], ubytes: [1, 4], b: true)
			try db.table(AllTypes.self).insert(model)

			guard let f = try db.table(AllTypes.self).where(\AllTypes.int == 1).first() else {
				return XCTFail("Nil result.")
			}
			XCTAssertEqual(model.int, f.int)
			XCTAssertEqual(model.uint, f.uint)
			XCTAssertEqual(model.int64, f.int64)
			XCTAssertEqual(model.uint64, f.uint64)
			XCTAssertEqual(model.int32, f.int32)
			XCTAssertEqual(model.uint32, f.uint32)
			XCTAssertEqual(model.int16, f.int16)
			XCTAssertEqual(model.uint16, f.uint16)
			XCTAssertEqual(model.int8, f.int8)
			XCTAssertEqual(model.uint8, f.uint8)
			XCTAssertEqual(model.double, f.double)
			XCTAssertEqual(model.float, f.float)
			XCTAssertEqual(model.string, f.string)
			XCTAssertEqual(model.bytes, f.bytes)
			XCTAssertEqual(model.ubytes!, f.ubytes!)
			XCTAssertEqual(model.b, f.b)
		} catch {
			XCTFail("\(error)")
		}
		do {
			let db = try getTestDB()
			try db.create(AllTypes.self, policy: .dropTable)
			let model = AllTypes(int: 1, uint: 2, int64: -3, uint64: 4, int32: nil, uint32: nil, int16: -7, uint16: 8, int8: nil, uint8: nil, double: -11, float: -12, string: "13", bytes: [1, 4], ubytes: nil, b: true)
			try db.table(AllTypes.self).insert(model)

			guard let f = try db.table(AllTypes.self)
				.where(\AllTypes.int == 1).first() else {
					return XCTFail("Nil result.")
			}
			XCTAssertEqual(model.int, f.int)
			XCTAssertEqual(model.uint, f.uint)
			XCTAssertEqual(model.int64, f.int64)
			XCTAssertEqual(model.uint64, f.uint64)
			XCTAssertEqual(model.int32, f.int32)
			XCTAssertEqual(model.uint32, f.uint32)
			XCTAssertEqual(model.int16, f.int16)
			XCTAssertEqual(model.uint16, f.uint16)
			XCTAssertEqual(model.int8, f.int8)
			XCTAssertEqual(model.uint8, f.uint8)
			XCTAssertEqual(model.double, f.double)
			XCTAssertEqual(model.float, f.float)
			XCTAssertEqual(model.string, f.string)
			XCTAssertEqual(model.bytes, f.bytes)
			XCTAssertNil(f.ubytes)
			XCTAssertEqual(model.b, f.b)
		} catch {
			XCTFail("\(error)")
		}
	}

	func testAllPrimTypes2() {
		struct AllTypes2: Codable {
			func equals(rhs: AllTypes2) -> Bool {
				guard int == rhs.int && uint == rhs.uint &&
					int64 == rhs.int64 && uint64 == rhs.uint64 &&
					int32 == rhs.int32 && uint32 == rhs.uint32 &&
					int16 == rhs.int16 && uint16 == rhs.uint16 &&
					int8 == rhs.int8 && uint8 == rhs.uint8 else {
						return false
				}
				guard double == rhs.double && float == rhs.float &&
					string == rhs.string &&
					b == rhs.b else {
						return false
				}
				guard (bytes == nil && rhs.bytes == nil) || (bytes != nil && rhs.bytes != nil) else {
					return false
				}
				guard (ubytes == nil && rhs.ubytes == nil) || (ubytes != nil && rhs.ubytes != nil) else {
					return false
				}
				if let lhsb = bytes {
					guard lhsb == rhs.bytes! else {
						return false
					}
				}
				if let lhsb = ubytes {
					guard lhsb == rhs.ubytes! else {
						return false
					}
				}
				return true
			}
			let int: Int?
			let uint: UInt?
			let int64: Int64?
			let uint64: UInt64?
			let int32: Int32?
			let uint32: UInt32?
			let int16: Int16?
			let uint16: UInt16?
			let int8: Int8?
			let uint8: UInt8?
			let double: Double?
			let float: Float?
			let string: String?
			let bytes: [Int8]?
			let ubytes: [UInt8]?
			let b: Bool?
		}

		do {
			let db = try getTestDB()
			try db.create(AllTypes2.self, policy: .dropTable)
			let model = AllTypes2(int: 1, uint: 2, int64: -3, uint64: 4, int32: 5, uint32: 6,
								  int16: 7, uint16: 8, int8: 9, uint8: 10,
								  double: 11.2, float: 12.3, string: "13",
								  bytes: [1, 4], ubytes: [1, 4], b: true)
			try db.table(AllTypes2.self).insert(model)
			do {
				guard let f = try db.table(AllTypes2.self)
					.where(\AllTypes2.int == 1 &&
						\AllTypes2.uint == 2 &&
						\AllTypes2.int64 == -3).first() else {
							return XCTFail("Nil result.")
				}
				XCTAssert(model.equals(rhs: f), "\(model) != \(f)")
				XCTAssertEqual(try db.table(AllTypes2.self)
					.where(\AllTypes2.int != 1 &&
						\AllTypes2.uint != 2 &&
						\AllTypes2.int64 != -3).count(), 0)
			}
			do {
				guard let f = try db.table(AllTypes2.self)
					.where(\AllTypes2.uint64 == 4 &&
						\AllTypes2.int32 == 5 &&
						\AllTypes2.uint32 == 6).first() else {
							return XCTFail("Nil result.")
				}
				XCTAssert(model.equals(rhs: f), "\(model) != \(f)")
				XCTAssertEqual(try db.table(AllTypes2.self)
					.where(\AllTypes2.uint64 != 4 &&
						\AllTypes2.int32 != 5 &&
						\AllTypes2.uint32 != 6).count(), 0)
			}
			do {
				guard let f = try db.table(AllTypes2.self)
					.where(\AllTypes2.int16 == 7 &&
						\AllTypes2.uint16 == 8 &&
						\AllTypes2.int8 == 9 &&
						\AllTypes2.uint8 == 10).first() else {
							return XCTFail("Nil result.")
				}
				XCTAssert(model.equals(rhs: f), "\(model) != \(f)")
				XCTAssertEqual(try db.table(AllTypes2.self)
					.where(\AllTypes2.int16 != 7 &&
						\AllTypes2.uint16 != 8 &&
						\AllTypes2.int8 != 9 &&
						\AllTypes2.uint8 != 10).count(), 0)
			}
			do {
				guard let f = try db.table(AllTypes2.self)
					.where(\AllTypes2.double == 11.2 &&
						\AllTypes2.float == Float(12.3) &&
						\AllTypes2.string == "13").first() else {
							return XCTFail("Nil result.")
				}
				XCTAssert(model.equals(rhs: f), "\(model) != \(f)")
				XCTAssertEqual(try db.table(AllTypes2.self)
					.where(\AllTypes2.double != 11.2 &&
						\AllTypes2.float != Float(12.3) &&
						\AllTypes2.string != "13").count(), 0)
			}
			do {
				guard let f = try db.table(AllTypes2.self)
					.where(\AllTypes2.bytes == [1, 4] as [Int8] &&
						\AllTypes2.ubytes == [1, 4] as [UInt8] &&
						\AllTypes2.b == true).first() else {
							return XCTFail("Nil result.")
				}
				XCTAssert(model.equals(rhs: f), "\(model) != \(f)")
				XCTAssertEqual(try db.table(AllTypes2.self)
					.where(\AllTypes2.bytes != [1, 4] as [Int8] &&
						\AllTypes2.ubytes != [1, 4] as [UInt8] &&
						\AllTypes2.b != true).count(), 0)
			}
		} catch {
			XCTFail("\(error)")
		}
	}

	func testBespokeSQL() {
		do {
			let db = try getTestDB()
			let r = try db.sql("SELECT * FROM \(TestTable1.CRUDTableName) WHERE id = 2", TestTable1.self)
			XCTAssertEqual(r.count, 1)
		} catch {
			XCTFail("\(error)")
		}
	}

	func testModelClasses() {
		class BaseClass: Codable {
			let id: Int
			let name: String
			private enum CodingKeys: String, CodingKey {
				case id, name
			}
			init(id: Int, name: String) {
				self.id = id
				self.name = name
			}
			required init(from decoder: Decoder) throws {
				let container = try decoder.container(keyedBy: CodingKeys.self)
				id = try container.decode(Int.self, forKey: .id)
				name = try container.decode(String.self, forKey: .name)
			}
			func encode(to encoder: Encoder) throws {
				var container = encoder.container(keyedBy: CodingKeys.self)
				try container.encode(id, forKey: .id)
				try container.encode(name, forKey: .name)
			}
		}

		class SubClass: BaseClass {
			let another: String
			private enum CodingKeys: String, CodingKey {
				case another
			}
			init(id: Int, name: String, another: String) {
				self.another = another
				super.init(id: id, name: name)
			}
			required init(from decoder: Decoder) throws {
				let container = try decoder.container(keyedBy: CodingKeys.self)
				another = try container.decode(String.self, forKey: .another)
				try super.init(from: decoder)
			}
			override func encode(to encoder: Encoder) throws {
				var container = encoder.container(keyedBy: CodingKeys.self)
				try container.encode(another, forKey: .another)
				try super.encode(to: encoder)
			}
		}

		do {
			let db = try getTestDB()
			try db.create(SubClass.self)
			let table = db.table(SubClass.self)
			let obj = SubClass(id: 1, name: "The name", another: "And another thing")
			try table.insert(obj)

			guard let found = try table.where(\SubClass.id == 1).first() else {
				return XCTFail("Did not find SubClass")
			}
			XCTAssertEqual(found.another, obj.another)
			XCTAssertEqual(found.name, obj.name)
		} catch {
			XCTFail("\(error)")
		}
	}

	func testURL() {
		do {
			let db = try getTestDB()
			struct TableWithURL: Codable {
				let id: Int
				let url: URL
			}
			try db.create(TableWithURL.self)
			let t1 = db.table(TableWithURL.self)
			let newOne = TableWithURL(id: 2000, url: URL(string: "http://localhost/")!)
			try t1.insert(newOne)
			let j1 = t1.where(\TableWithURL.id == newOne.id)
			let j2 = try j1.select().map {$0}
			XCTAssertEqual(try j1.count(), 1)
			XCTAssertEqual(j2[0].id, 2000)
			XCTAssertEqual(j2[0].url.absoluteString, "http://localhost/")
		} catch {
			XCTFail("\(error)")
		}
	}
	// swiftlint: disable colon opening_brace
	func testManyJoins() {
		do {
			let db = try getTestDB()

			struct Person2 : Codable{
				var id : UUID
				var name : String
				let cars : [Car]?
				let boats : [Boat]?
				let houses : [House]?
			}
			struct Car : Codable{
				var id : UUID
				var owner : UUID
			}
			struct Boat : Codable{
				var id : UUID
				var owner : UUID
			}
			struct House : Codable{
				var id : UUID
				var owner : UUID
			}
			try db.create(Person2.self)
			try db.table(Car.self).index(\.owner)
			try db.table(Boat.self).index(\.owner)
			try db.table(House.self).index(\.owner)

			let t1 = db.table(Person2.self)
			let parentId = UUID()
			let person = Person2(id: parentId, name: "The Person", cars: nil, boats: nil, houses: nil)
			try t1.insert(person)

			for _ in 0..<5 {
				try  db.table(Car.self).insert(.init(id: UUID(), owner: parentId))
				try db.table(Boat.self).insert(.init(id: UUID(), owner: parentId))
				try db.table(House.self).insert(.init(id: UUID(), owner: parentId))
			}

			let j1 = try t1.join(\.cars, on: \.id, equals: \.owner)
							.join(\.boats, on: \.id, equals: \.owner)
							.join(\.houses, on: \.id, equals: \.owner)
							.where(\Person2.id == parentId)
			guard let j2 = try j1.first() else {
                return XCTFail("join")
			}
			XCTAssertEqual(5, j2.cars?.count)
			XCTAssertEqual(5, j2.boats?.count)
			XCTAssertEqual(5, j2.houses?.count)
		} catch {
			XCTFail("\(error)")
		}
	}

	func testAssets() {
		struct Asset: Codable {
			let id: UUID
			let name: String?
			let assetLog: [AssetLog]?
			init(id i: UUID,
				 name n: String? = nil,
				 assetLog log: [AssetLog]? = nil) {
				id = i
				name = n
				assetLog = log
			}
		}

		struct AssetLog: Codable {
			let assetId: UUID
			let userId: UUID
			let taken: Double
			let returned: Double?
			init(assetId: UUID, userId: UUID, taken: Double, returned: Double? = nil) {
				self.assetId = assetId
				self.userId = userId
				self.taken = taken
				self.returned = returned
			}
		}

		do {
			let db = try getTestDB()
			try db.create(Asset.self, policy: .dropTable)
			let id = UUID()
			let userId = UUID()
			do {
				let asset = Asset(id: id, name: "name")
				try db.table(Asset.self).insert(asset)
				let assetLogs = [AssetLog(assetId: id, userId: userId, taken: 1.0),
								 AssetLog(assetId: id, userId: userId, taken: 2.0)]
				try db.table(AssetLog.self).insert(assetLogs)
			}
			let assetTable = db.table(Asset.self)
			let asset = try assetTable.join(\.assetLog, on: \.id, equals: \.assetId)
				.where(\AssetLog.userId == userId && \AssetLog.returned == nil).first()
			XCTAssertNotNil(asset?.assetLog)
			XCTAssertEqual(asset?.id, id)
			XCTAssertEqual(asset?.assetLog?.count, 2)
		} catch {
			XCTFail("\(error)")
		}

	}

	func testEmptyInsert() {
		do {
			let db = try getTestDB()
			struct ReturningItem: Codable, Equatable {
				let id: Int?
				var def: Int?
				init(id: Int, def: Int? = nil) {
					self.id = id
					self.def = def
				}
			}
			try db.sql("DROP TABLE IF EXISTS \(ReturningItem.CRUDTableName)")
			try db.sql("CREATE TABLE \(ReturningItem.CRUDTableName) (id INT PRIMARY KEY, def INT DEFAULT 42)")
			let table = db.table(ReturningItem.self)

			let id = try table
				.insert(ReturningItem(id: 0, def: 0),
						ignoreKeys: \ReturningItem.id, \ReturningItem.def)
				.lastInsertId()
			XCTAssertEqual(id, 1)

		} catch {
			XCTFail("\(error)")
		}
	}

	func testLastInsertId() {
		do {
			let db = try getTestDB()
			struct ReturningItem: Codable, Equatable {
				let id: Int?
				var def: Int?
				init(id: Int, def: Int? = nil) {
					self.id = id
					self.def = def
				}
			}
			try db.sql("DROP TABLE IF EXISTS \(ReturningItem.CRUDTableName)")
			try db.sql("CREATE TABLE \(ReturningItem.CRUDTableName) (id INT PRIMARY KEY, def INT DEFAULT 42)")
			let table = db.table(ReturningItem.self)

			let id = try table
				.insert(ReturningItem(id: 0, def: 0),
						ignoreKeys: \ReturningItem.id)// , \ReturningItem.def)
				.lastInsertId()
			XCTAssertEqual(id, 1)

		} catch {
			XCTFail("\(error)")
		}
	}
}
