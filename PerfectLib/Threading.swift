//
//  Threading.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2015-12-03.
//  Copyright © 2015 PerfectlySoft. All rights reserved.
//

#if USE_LIBDISPATCH
import Dispatch
#else
#if os(Linux)
import SwiftGlibc
#else
import Darwin
#endif
#endif

class Threading {
	
	typealias ThreadOnceFunction = @convention(c) () -> ()
	
#if USE_LIBDISPATCH
	typealias ThreadClosure = () -> ()
	typealias ThreadQueue = dispatch_queue_t
	typealias ThreadSemaphore = dispatch_semaphore_t
	typealias ThreadOnce = dispatch_once_t
#else
	
	class ThreadSemaphore {
		
		var mutex = pthread_mutex_t()
		var cond = pthread_cond_t()
		
		init() {
			var attr = pthread_mutexattr_t()
			pthread_mutexattr_init(&attr)
			pthread_mutexattr_settype(&attr, Int32(PTHREAD_MUTEX_RECURSIVE))
			pthread_mutex_init(&mutex, &attr)
			
			var __c_attr = pthread_condattr_t()
			pthread_condattr_init(&__c_attr)
#if os (Linux)
//			pthread_condattr_setclock(&__c_attr, CLOCK_REALTIME)
#endif
			pthread_cond_init(&cond, &__c_attr)
			pthread_condattr_destroy(&__c_attr)
		}
		
		deinit {
			pthread_cond_destroy(&cond)
			pthread_mutex_destroy(&mutex)
		}
	}
	
	typealias ThreadClosure = () -> ()
	typealias ThreadQueue = Int // bogus
	typealias ThreadOnce = pthread_once_t
	typealias ThreadFunction = @convention(c) (UnsafeMutablePointer<Void>) -> UnsafeMutablePointer<Void>
	
	class IsThisRequired {
		let closure: ThreadClosure
		init(closure: ThreadClosure) {
			self.closure = closure
		}
	}
#endif
	
	static func dispatchBlock(closure: ThreadClosure) {
#if USE_LIBDISPATCH
		dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), closure)
#else
		var thrdSlf = pthread_t()
		var attr = pthread_attr_t()
		pthread_attr_init(&attr)
		pthread_attr_setdetachstate(&attr, Int32(PTHREAD_CREATE_DETACHED))
		
		let holderObject = IsThisRequired(closure: closure)
		
		let pthreadFunc: ThreadFunction = {
			p in
			
			let unleakyObject = Unmanaged<IsThisRequired>.fromOpaque(COpaquePointer(p)).takeRetainedValue()
			
			unleakyObject.closure()
			
			return nil
		}
		
		let leakyObject = UnsafeMutablePointer<Void>(Unmanaged.passRetained(holderObject).toOpaque())
		pthread_create(&thrdSlf, &attr, pthreadFunc, leakyObject)
#endif
	}
	
	static func dispatchBlock(queue: ThreadQueue, closure: ThreadClosure) {
#if USE_LIBDISPATCH
		dispatch_async(queue, closure)
#else
		Threading.dispatchBlock(closure)
#endif
	}
	
	static func createSerialQueue(named: String) -> ThreadQueue {
#if USE_LIBDISPATCH
		return dispatch_queue_create(named, DISPATCH_QUEUE_SERIAL)
#else
		return Threading.createConcurrentQueue(named) // whoops!
#endif
	}
	
	static func createConcurrentQueue(named: String) -> ThreadQueue {
#if USE_LIBDISPATCH
		return dispatch_queue_create(named, DISPATCH_QUEUE_CONCURRENT)
#else
		return 1
#endif
	}
	
	static func createSemaphore() -> ThreadSemaphore {
#if USE_LIBDISPATCH
		return dispatch_semaphore_create(0)
#else
		return ThreadSemaphore()
#endif
	}
	
	static func signalSemaphore(semaphore: ThreadSemaphore) {
#if USE_LIBDISPATCH
		dispatch_semaphore_signal(semaphore)
#else
		pthread_mutex_lock(&semaphore.mutex)
		pthread_cond_signal(&semaphore.cond)
		pthread_mutex_unlock(&semaphore.mutex)
#endif
	}
	
	static func waitSemaphore(semaphore: ThreadSemaphore, waitMillis: Int) {
		if waitMillis == -1 {
#if USE_LIBDISPATCH
			dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER)
#else
			pthread_mutex_lock(&semaphore.mutex)
			pthread_cond_wait(&semaphore.cond, &semaphore.mutex)
			pthread_mutex_unlock(&semaphore.mutex)
#endif
		} else {
			// !FIX!
		}
	}
	
	static func once(inout threadOnce: ThreadOnce, onceFunc: ThreadOnceFunction) {
#if USE_LIBDISPATCH
		dispatch_once(&threadOnce, onceFunc)
#else
		pthread_once(&threadOnce, onceFunc)
#endif
	}
}





