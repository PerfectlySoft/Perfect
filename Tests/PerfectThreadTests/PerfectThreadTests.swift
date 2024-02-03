//
//  Package.swift
//  PerfectThread
//
//  Created by Kyle Jessup on 2016-05-02.
//	Copyright (C) 2016 PerfectlySoft, Inc.
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

#if os(Linux)
    import LinuxBridge
#else
    import Darwin
#endif

import XCTest
@testable import PerfectThread

class PerfectThreadTests: XCTestCase {

    func testConcurrentQueue1() {
        let q = Threading.getQueue(name: "concurrent", type: .concurrent)

        var t1 = 0, t2 = 0, t3 = 0

        q.dispatch {
            t1 = 1
            Threading.sleep(seconds: 5)
        }
        q.dispatch {
            t2 = 1
            Threading.sleep(seconds: 5)
        }
        q.dispatch {
            t3 = 1
            Threading.sleep(seconds: 5)
        }
        Threading.sleep(seconds: 1)

        XCTAssert(t1 == 1 && t2 == 1 && t3 == 1)
    }

	func testConcurrentQueue2() {
		_ = Threading.getQueue(name: "concurrent", type: .concurrent)
		var expects = [XCTestExpectation]()
		let threadCount = 32
		let iterationCount = 10000
		for n in 0..<threadCount {
			expects.append(self.expectation(description: "ex\(n)"))
		}

		for i in 0..<threadCount {
			Threading.dispatch {
				var countDown = iterationCount
				let event = Threading.Event()
				for _ in 0..<iterationCount {
					let queue = Threading.getQueue(name: "concurrent", type: .concurrent)
					queue.dispatch {
						event.lock()
						countDown -= 1
						event.signal()
						event.unlock()
					}
				}
				while true {
					event.lock()
					defer { event.unlock() }
					if countDown == 0 {
						break
					}
					_ = event.wait()
				}
				expects[i].fulfill()
			}
		}
        self.waitForExpectations(timeout: 60.0) { _ in }
	}

    func testSerialQueue() {
        let q = Threading.getQueue(name: "serial", type: .serial)

        var t1 = 0

        q.dispatch {
            XCTAssert(t1 == 0)
            t1 = 1
        }
        q.dispatch {
            XCTAssert(t1 == 1)
            t1 = 2
        }
        q.dispatch {
            XCTAssert(t1 == 2)
            t1 = 3
        }
        Threading.sleep(seconds: 2)
        XCTAssert(t1 == 3)
    }

    func testThreadSleep() {

        func getNow() -> Double {
            var posixTime = timeval()
            gettimeofday(&posixTime, nil)
            return Double(posixTime.tv_sec * 1000 + Int(posixTime.tv_usec) / 1000)
        }

        let now = getNow()
        Threading.sleep(seconds: 1.9)
        let nower = getNow()
        XCTAssert(nower - now >= 2.0)
    }

	func testEventTimeout() {
		let event = Threading.Event()
		event.lock()
		let startTime = time(nil)
		let waitRes = event.wait(seconds: 2.0)
		let endTime = time(nil)
		event.unlock()
		XCTAssert(waitRes == false)
		XCTAssert(endTime - startTime >= 2)
		XCTAssert(endTime - startTime < 3)
	}

	func testPromise1() {
		let p = Promise<Bool> { (p: Promise) in
			Threading.sleep(seconds: 2.0)
			p.set(true)
		}

		XCTAssert(try p.get() == nil)
		XCTAssert(try p.wait(seconds: 3.0) == true)
	}

	func testPromise2() {

		struct Exception: Error {}

		let p = Promise<Bool> { (p: Promise) in
			Threading.sleep(seconds: 2.0)
			p.fail(Exception())
		}

		XCTAssert(try p.get() == nil)
		do {
			_ = try p.wait(seconds: 3.0)
			XCTAssert(false)
		} catch {
			XCTAssert(error is Exception)
		}
	}

	func testPromise3() {
		do {
			let v = try Promise { 1 }.then { try $0() + 1 }.then { try $0() + 1 }.wait()
			XCTAssert(v == 3, "\(String(describing: v))")
		} catch {
			XCTAssert(false, "\(error)")
		}
	}

	func testPromise4() {
		struct Exception: Error {}
		do {
			let v = try Promise { throw Exception() }.then { try $0() + 1 }.then { try $0() + 1 }.wait()
			XCTAssert(false, "\(String(describing: v))")
		} catch {
			XCTAssert(error is Exception)
		}
	}

	func testPromise5() {
		do {
			for _ in 0..<100000 {
				let v = try Promise { 1 }
					.then { try $0() + 2 }
					.then { try $0() + 3 }
					.wait()
				XCTAssert(v == 6, "\(String(describing: v))")
			}
		} catch {
			XCTAssert(false, "\(error)")
		}
	}

	func testPromiseFail() {
		struct Exception: Error {}
		let exp = expectation(description: "wait")
		var err = false
		_ = Promise { 1 }.then {
			_ = try $0()
			throw Exception()
		}.when { _ in
			err = true
			exp.fulfill()
		}
		waitForExpectations(timeout: 3) { _ in }
		XCTAssert(err)
	}

	func testDoWithLock() {
		let lock = Threading.Lock()
		lock.doWithLock { // test compilation of no return usage
			for _ in 0...1 {
				()
			}
		}
		let result = lock.doWithLock {
			return "foo"
		}
		XCTAssertEqual(result, "foo")
	}
}
