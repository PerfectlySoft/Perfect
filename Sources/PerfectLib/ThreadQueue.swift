//
//  ThreadQueue.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2016-04-08.
//  Copyright © 2016 PerfectlySoft. All rights reserved.
//

#if os(Linux)
	import SwiftGlibc
	import LinuxBridge
#else
	import Darwin
#endif

public protocol ThreadQueue {
	var name: String { get }
	var type: Threading.QueueType { get }
	func dispatch(closure: Threading.ThreadClosure)
}

public extension Threading {
	
	private static var serialQueues = [String:ThreadQueue]()
	private static var concurrentQueues = [String:ThreadQueue]()
	private static let queuesLock = Threading.Lock()
	
	public enum QueueType {
		case Serial
		case Concurrent
	}
	
	private class SerialQueue: ThreadQueue {
		let name: String
		let type = Threading.QueueType.Serial
		
		private typealias ThreadFunc = Threading.ThreadClosure
		private let lock = Threading.Event()
		private var q = [ThreadFunc]()
		
		init(name: String) {
			self.name = name
			self.startLoop()
		}
		
		func dispatch(closure: Threading.ThreadClosure) {
			self.lock.doWithLock {
				self.q.append(closure)
				self.lock.signal()
			}
		}
		
		private func startLoop() {
			Threading.dispatchOnNewThread {
				
				while true {
					
					var block: SerialQueue.ThreadFunc?
					self.lock.doWithLock {
						if self.q.count > 0 {
							block = self.q.removeFirst()
						} else {
							self.lock.wait()
						}
					}
					
					if let b = block {
						b()
					}
				}
			}
		}
	}
	
	private class ConcurrentQueue: ThreadQueue {
		let name: String
		let type = Threading.QueueType.Serial
		
		private typealias ThreadFunc = Threading.ThreadClosure
		private let lock = Threading.Event()
		private var q = [ThreadFunc]()
		
		init(name: String) {
			self.name = name
			self.startLoop()
		}
		
		func dispatch(closure: Threading.ThreadClosure) {
			self.lock.doWithLock {
				self.q.append(closure)
				self.lock.signal()
			}
		}
		
		private func startLoop() {
			for _ in 0..<max(4, Threading.processorCount) {
				Threading.dispatchOnNewThread {
					
					while true {
						
						var block: SerialQueue.ThreadFunc?
						self.lock.doWithLock {
							if self.q.count > 0 {
								block = self.q.removeFirst()
							} else {
								self.lock.wait()
							}
						}
						
						if let b = block {
							b()
						}
					}
				}
			}
		}
	}
	
	static var processorCount: Int {
		let num = sysconf(_SC_NPROCESSORS_ONLN)
		return num
	}
	
	static func getQueue(name: String, type: QueueType) -> ThreadQueue {
		var q: ThreadQueue?
		Threading.queuesLock.doWithLock {
			switch type {
			case .Serial:
				if let qTst = Threading.serialQueues[name] {
					q = qTst
				} else {
					q = SerialQueue(name: name)
					Threading.serialQueues[name] = q
				}
			case .Concurrent:
				if let qTst = Threading.concurrentQueues[name] {
					q = qTst
				} else {
					q = ConcurrentQueue(name: name)
					Threading.concurrentQueues[name] = q
				}
			}
		}
		return q!
	}
	/// Call the given closure on the "default" concurrent queue
	/// Returns immediately.
	public static func dispatchBlock(closure: Threading.ThreadClosure) {
		let q = Threading.getQueue("default", type: .Concurrent)
		q.dispatch(closure)
	}
	
	// This is a lower level function which does not utilize the ThreadQueue system.
	private static func dispatchOnNewThread(closure: ThreadClosure) {
		var thrdSlf = pthread_t(nil)
		var attr = pthread_attr_t()
		pthread_attr_init(&attr)
		pthread_attr_setdetachstate(&attr, Int32(PTHREAD_CREATE_DETACHED))
		
		let holderObject = IsThisRequired(closure: closure)
		
		let pthreadFunc: ThreadFunction = {
			p in
			
			let unleakyObject = Unmanaged<IsThisRequired>.fromOpaque(OpaquePointer(p)).takeRetainedValue()
			
			unleakyObject.closure()
			
			return nil
		}
		
		let leakyObject = UnsafeMutablePointer<Void>(OpaquePointer(bitPattern: Unmanaged.passRetained(holderObject)))
		pthread_create(&thrdSlf, &attr, pthreadFunc, leakyObject)
	}
	
}

