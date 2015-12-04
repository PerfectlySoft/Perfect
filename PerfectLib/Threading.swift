//
//  Threading.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2015-12-03.
//  Copyright © 2015 PerfectlySoft. All rights reserved.
//

#if os(Linux)
import SwiftGlibc
#else
import Dispatch
#endif

class Threading {
	#if os(Linux)
	
	#else
	typealias ThreadClosure = () -> ()
	typealias ThreadQueue = dispatch_queue_t
	typealias ThreadSemaphore = dispatch_semaphore_t
	typealias ThreadOnce = dispatch_once_t
	#endif
	
	static func dispatchBlock(closure: ThreadClosure) {
		
		#if os(Linux)
		
		#else
			dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), closure)
		#endif
		
	}
	
	static func dispatchBlock(queue: ThreadQueue, closure: ThreadClosure) {
		
		#if os(Linux)
			
		#else
			dispatch_async(queue, closure)
		#endif
		
	}
	
	static func createSerialQueue(named: String) -> ThreadQueue {
		
		#if os(Linux)
		return Threading.createConcurrentQueue(named) // whoops!
		#else
		return dispatch_queue_create(named, DISPATCH_QUEUE_SERIAL)
		#endif
	}
	
	static func createConcurrentQueue(named: String) -> ThreadQueue {
		
		#if os(Linux)
			
		#else
			return dispatch_queue_create(named, DISPATCH_QUEUE_CONCURRENT)
		#endif
	}
	
	static func signalSemaphore(semaphore: ThreadSemaphore) {
		
		#if os(Linux)
		
		#else
		dispatch_semaphore_signal(semaphore)
		#endif
	}
	
	static func createSemaphore() -> ThreadSemaphore {
		#if os(Linux)
			
		#else
		return dispatch_semaphore_create(0)
		#endif
	}
	
	static func waitSemaphore(semaphore: ThreadSemaphore, waitMillis: Int) {
		if waitMillis == -1 {
			#if os(Linux)
			
			#else
			dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER)
			#endif
		} else {
			
		}
	}
	
	static func once(inout threadOnce: ThreadOnce, closure: ThreadClosure) {
		#if os(Linux)
		
		#else
		dispatch_once(&threadOnce, closure)
		#endif
	}
}





