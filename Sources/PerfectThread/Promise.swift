//
//  Promise.swift
//  PerfectThread
//
//  Created by Kyle Jessup on 2017-03-06.
//	Copyright (C) 2017 PerfectlySoft, Inc.
//
// ===----------------------------------------------------------------------===//
//
// This source file is part of the Perfect.org open source project
//
// Copyright (c) 2015 - 2017 PerfectlySoft Inc. and the Perfect project authors
// Licensed under Apache License v2.0
//
// See http://perfect.org/licensing.html for license information
//
// ===----------------------------------------------------------------------===//
//

/// A Promise is an object which is shared between one or more threads. 
/// The promise will execute the closure given to it when it is created on a new thread. When the
/// thread produces its return value a consumer thread will be able to obtain 
/// the value or handle the error if one occurred.
///
/// This object is generally used in one of two ways:
///	  * By passing a closure/function which is executed on another thread and accepts the
///		Promise as a parameter. The promise can at some later point be .set or .fail'ed, with a 
///		return value or error object, respectively. The Promise creator can periodically .get
///		or .wait for the value or error. This provides the most flexible usage as the Promise can be 
///		.set at any point, for example after a series of asynchronous API calls.
///		Example:
///		let prom = Promise<Bool> {
///			(p: Promise) in
///			Threading.sleep(seconds: 2.0)
///			p.set(true)
///		}
///		XCTAssert(try prom.get() == nil) // not fulfilled yet
///		XCTAssert(try prom.wait(seconds: 3.0) == true)
///
///	  * By passing a closure/function which accepts zero parameters and returns some abitrary type,
///		followed by zero or more calls to .then
///		Example:
///		let v = try Promise { 1 }.then { try $0() + 1 }.then { try $0() + 1 }.wait()
///		XCTAssert(v == 3, "\(v)")
///

import Dispatch

public class Promise<ReturnType> {

	let event = Threading.Event()
	let queue = DispatchQueue(label: "promise")
	var value: ReturnType?
	var error: Error?

	/// Initialize a Promise with a closure. The closure is passed the promise object on which the
	/// return value or error can be later set.
	/// The closure will be executed on a new serial thread queue and will begin 
	/// executing immediately.
	public init(closure: @escaping (Promise<ReturnType>) throws -> ()) {
		queue.async {
			do {
				try closure(self)
			} catch {
				self.fail(error)
			}
		}
	}

	/// Initialize a Promise with a closure. The closure will return a single value type which will
	/// fulfill the promise.
	/// The closure will be executed on a new serial thread queue and will begin
	/// executing immediately.
	public init(closure: @escaping () throws -> ReturnType) {
		queue.async {
			do {
				self.set(try closure())
			} catch {
				self.fail(error)
			}
		}
	}

	init<LastType>(from: Promise<LastType>, closure: @escaping (() throws -> LastType) throws -> ReturnType) {
		queue.async {
			do {
				self.set(try closure({ guard let v = try from.wait() else { throw BrokenPromise() } ; return v }))
			} catch {
				self.fail(error)
			}
		}
	}

	/// Chain a new Promise to an existing. The provided closure will receive the previous promise's 
	/// value once it is available and should return a new value.
	public func then<NewType>(closure: @escaping (() throws -> ReturnType) throws -> NewType) -> Promise<NewType> {
		return Promise<NewType>(from: self, closure: closure)
	}

	public func when(closure: @escaping (Error) throws -> ()) -> Promise<ReturnType> {
		return Promise<ReturnType>(from: self) { value in
			do {
				return try value()
			} catch {
				try closure(error)
				throw error
			}
		}
	}
}

public extension Promise {
	/// Get the return value if it is available.
	/// Returns nil if the return value is not available.
	/// If a failure has occurred then the Error will be thrown.
	/// This is called by the consumer thread.
	func get() throws -> ReturnType? {
		event.lock()
		defer {
			event.unlock()
		}
		if let error = error {
			throw error
		}
		return value
	}

	/// Get the return value if it is available.
	/// Returns nil if the return value is not available.
	/// If a failure has occurred then the Error will be thrown.
	/// Will block and wait up to the indicated number of seconds for the return value to be produced.
	/// This is called by the consumer thread.
	func wait(seconds: Double = Threading.noTimeout) throws -> ReturnType? {
		event.lock()
		defer {
			event.unlock()
		}
		if let error = error {
			throw error
		}
		if let value = value {
			return value
		}
		repeat {
			if let error = error {
				throw error
			}
			if let value = value {
				return value
			}
		} while event.wait(seconds: seconds)
		if let error = error {
			throw error
		}
		return value
	}
}

public extension Promise {
	/// Set the Promise's return value, enabling the consumer to retrieve it.
	/// This is called by the producer thread.
	func set(_ value: ReturnType) {
		event.lock()
		defer {
			event.unlock()
		}
		self.value = value
		event.broadcast()
	}

	/// Fail the Promise and set its error value.
	/// This is called by the producer thread.
	func fail(_ error: Error) {
		event.lock()
		defer {
			event.unlock()
		}
		self.error = error
		event.broadcast()
	}
}

struct BrokenPromise: Error {}
