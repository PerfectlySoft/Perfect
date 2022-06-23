//
//	ThreadQueue.swift
//	PerfectLib
//
//	Created by Kyle Jessup on 2016-04-08.
//	Copyright © 2016 PerfectlySoft. All rights reserved.
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
	import SwiftGlibc
	import LinuxBridge
#else
	import Foundation
#endif

import Dispatch

private let anonymousQueueName = "__unregistered__"

/// A thread queue which can dispatch a closure according to the queue type.
public protocol ThreadQueue {
	/// The queue name.
	var name: String { get }
	/// The queue type.
	var type: Threading.QueueType { get }
	/// Execute the given closure within the queue's thread.
	func dispatch(_ closure: @escaping Threading.ThreadClosure)
}

protocol ThreadQueueInternal {
	var running: Bool { get set }
	var lock: Threading.Event { get }
}

public extension Threading {

	private static var serialQueues = [String: ThreadQueue]()
	private static var concurrentQueues = [String: ThreadQueue]()
	private static let queuesLock = Threading.Lock()

	private static let defaultQueue = DefaultQueue()

	/// Queue type indicator.
	enum QueueType {
		/// A queue which operates on only one thread.
		case serial
		/// A queue which operates on a number of threads, usually equal to the number of logical CPUs.
		case concurrent
	}

	private class DefaultQueue: ThreadQueue {
		let name = "default"
		let type = Threading.QueueType.concurrent
		let queue = DispatchQueue(label: "default", attributes: .concurrent)
		@inline(__always)
		final func dispatch(_ closure: @escaping Threading.ThreadClosure) {
			queue.async(execute: closure)
		}
	}

	private class SerialQueue: ThreadQueue, ThreadQueueInternal {
		let name: String
		let type = Threading.QueueType.serial
		var running = true
		let lock = Threading.Event()
		private var q: [Threading.ThreadClosure] = []

		init(name: String) {
			self.name = name
			self.startLoop()
		}

		func dispatch(_ closure: @escaping Threading.ThreadClosure) {
			_ = self.lock.lock()
			defer { _ = self.lock.unlock() }
			self.q.append(closure)
			_ = self.lock.signal()
		}

		private func startLoop() {
			Threading.dispatchOnNewThread {
				while self.running {
					var block: Threading.ThreadClosure?
					do {
						self.lock.lock()
						defer { self.lock.unlock() }

						let count = self.q.count
						if count > 0 {
							block = self.q.removeFirst()
						} else {
							_ = self.lock.wait()
							if self.q.count > 0 {
								block = self.q.removeFirst()
							}
						}
					}
					if let b = block {
						#if os(macOS)
							autoreleasepool { b() }
						#else
							b()
						#endif
					}
				}
			}
		}
	}

	private class ConcurrentQueue: ThreadQueue, ThreadQueueInternal {
		let name: String
		let type = Threading.QueueType.concurrent
		var running = true
		let lock = Threading.Event()
		private var q: [Threading.ThreadClosure] = []

		init(name: String) {
			self.name = name
			self.startLoop()
		}

		func dispatch(_ closure: @escaping Threading.ThreadClosure) {
			_ = self.lock.lock()
			defer { _ = self.lock.unlock() }
			self.q.append(closure)
			_ = self.lock.signal()
		}

		private func startLoop() {
			for _ in 0..<max(4, Threading.processorCount) {
				Threading.dispatchOnNewThread {
					while self.running {
						var block: Threading.ThreadClosure?
						do {
							_ = self.lock.lock()
							defer { _ = self.lock.unlock() }

							let count = self.q.count
							if count > 0 {
								block = self.q.removeFirst()
							} else {
								_ = self.lock.wait()
								if self.q.count > 0 {
									block = self.q.removeFirst()
								}
							}
						}
						if let b = block {
							#if os(macOS)
								autoreleasepool { b() }
							#else
								b()
							#endif
						}
					}
				}
			}
		}
	}

	private static var processorCount: Int {
		#if os(Linux)
			let num = sysconf(Int32(_SC_NPROCESSORS_ONLN))
		#else
			let num = sysconf(_SC_NPROCESSORS_ONLN)
		#endif
		return num
	}

	/// Return the default queue
	static func getDefaultQueue() -> ThreadQueue {
		return defaultQueue
	}

	/// Returns an anonymous queue of the indicated type.
	/// This queue can not be utilized without the returned ThreadQueue object.
	/// The queue should be destroyed when no longer needed.
	static func getQueue(type: QueueType) -> ThreadQueue {
		switch type {
		case .serial:
			return SerialQueue(name: anonymousQueueName)
		case .concurrent:
			return ConcurrentQueue(name: anonymousQueueName)
		}
	}

	/// Find or create a queue indicated by name and type.
	static func getQueue(name: String, type: QueueType) -> ThreadQueue {
		Threading.queuesLock.lock()
		defer { Threading.queuesLock.unlock() }

		switch type {
		case .serial:
			if let qTst = Threading.serialQueues[name] {
				return qTst
			}
			let q = SerialQueue(name: name)
			Threading.serialQueues[name] = q
			return q
		case .concurrent:
			if let qTst = Threading.concurrentQueues[name] {
				return qTst
			}
			let q = ConcurrentQueue(name: name)
			Threading.concurrentQueues[name] = q
			return q
		}
	}

	/// Terminate and remove a thread queue.
	static func destroyQueue(_ queue: ThreadQueue) {
		if queue.name != anonymousQueueName {
			Threading.queuesLock.lock()
			defer { Threading.queuesLock.unlock() }
            switch queue.type {
            case .serial:
                Threading.serialQueues.removeValue(forKey: queue.name)
            case .concurrent:
                Threading.concurrentQueues.removeValue(forKey: queue.name)
			}
		}
		if var qi = queue as? ThreadQueueInternal {
			qi.running = false
			qi.lock.broadcast()
		}
	}

	/// Call the given closure on the "default" concurrent queue
	/// Returns immediately.
	static func dispatch(closure: @escaping Threading.ThreadClosure) {
		defaultQueue.dispatch(closure)
	}

	// This is a lower level function which does not utilize the ThreadQueue system.
	private static func dispatchOnNewThread(closure: @escaping ThreadClosure) {
		#if os(Linux)
			var thrdSlf = pthread_t()
		#else
			var thrdSlf = pthread_t(nil as OpaquePointer?)
		#endif
		var attr = pthread_attr_t()

		pthread_attr_init(&attr)
		pthread_attr_setdetachstate(&attr, Int32(PTHREAD_CREATE_DETACHED))

		final class IsThisRequired {
			let closure: ThreadClosure
			init(closure: @escaping ThreadClosure) {
				self.closure = closure
			}
		}

		let holderObject = IsThisRequired(closure: closure)
		#if os(Linux)
            typealias ThreadFunction = @convention(c) (UnsafeMutableRawPointer?) -> UnsafeMutableRawPointer?
            let pthreadFunc: ThreadFunction = { p in
                guard let p = p else {
                    return nil
                }
                let unleakyObject = Unmanaged<IsThisRequired>.fromOpaque(UnsafeMutableRawPointer(p)).takeRetainedValue()
                unleakyObject.closure()
                return nil
            }
        #else
			typealias ThreadFunction = @convention(c) (UnsafeMutableRawPointer) -> UnsafeMutableRawPointer?
			let pthreadFunc: ThreadFunction = { p in
				let unleakyObject = Unmanaged<IsThisRequired>.fromOpaque(UnsafeMutableRawPointer(p)).takeRetainedValue()
				unleakyObject.closure()
				return nil
			}
		#endif
		let leakyObject = Unmanaged.passRetained(holderObject).toOpaque()
		pthread_create(&thrdSlf, &attr, pthreadFunc, leakyObject)
	}
}
