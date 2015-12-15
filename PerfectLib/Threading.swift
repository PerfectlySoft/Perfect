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

public class Threading {
	
	public typealias ThreadOnceFunction = @convention(c) () -> ()
	
#if USE_LIBDISPATCH
	public typealias ThreadClosure = () -> ()
	public typealias ThreadQueue = dispatch_queue_t
	public typealias ThreadOnce = dispatch_once_t
#else
	
	public typealias ThreadClosure = () -> ()
	public typealias ThreadQueue = Int // bogus
	public typealias ThreadOnce = pthread_once_t
	public typealias ThreadFunction = @convention(c) (UnsafeMutablePointer<Void>) -> UnsafeMutablePointer<Void>
	
	class IsThisRequired {
		let closure: ThreadClosure
		init(closure: ThreadClosure) {
			self.closure = closure
		}
	}
#endif
	
	public class Lock {
		
		var mutex = pthread_mutex_t()
		
		public init() {
			var attr = pthread_mutexattr_t()
			pthread_mutexattr_init(&attr)
			pthread_mutexattr_settype(&attr, Int32(PTHREAD_MUTEX_RECURSIVE))
			pthread_mutex_init(&mutex, &attr)
		}
		
		deinit {
			pthread_mutex_destroy(&mutex)
		}
		
		public func lock() {
			pthread_mutex_lock(&self.mutex)
		}
		
		public func unlock() {
			pthread_mutex_unlock(&self.mutex)
		}
		
	}
	
	public class Event: Lock {
		
		var cond = pthread_cond_t()
		
		override init() {
			super.init()
			
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
		}
		
		public func signal() {
			pthread_cond_signal(&self.cond)
		}
		
		public func wait(waitMillis: Int = -1) -> Bool {
			if waitMillis == -1 {
				return 0 == pthread_cond_wait(&self.cond, &self.mutex)
			}
			var tm = timespec()
		#if os(Linux)
			var tv = timeval()
			gettimeofday(&tv, nil)
			tm.tv_sec = tv.tv_sec + waitMillis / 1000;
			tm.tv_nsec = (tv.tv_usec + 1000 * waitMillis) * 1000
			let ret = pthread_cond_timedwait(&self.cond, &self.mutex, &tm)
		#else
			tm.tv_sec = waitMillis / 1000
			tm.tv_nsec = (waitMillis - (tm.tv_sec * 1000)) * 1000000
			
			let ret = pthread_cond_timedwait_relative_np(&self.cond, &self.mutex, &tm)
		#endif
			return ret == 0;
		}
	}
	
	public static func dispatchBlock(closure: ThreadClosure) {
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
	
	public static func dispatchBlock(queue: ThreadQueue, closure: ThreadClosure) {
#if USE_LIBDISPATCH
		dispatch_async(queue, closure)
#else
		Threading.dispatchBlock(closure)
#endif
	}
	
	public static func createSerialQueue(named: String) -> ThreadQueue {
#if USE_LIBDISPATCH
		return dispatch_queue_create(named, DISPATCH_QUEUE_SERIAL)
#else
		return Threading.createConcurrentQueue(named) // whoops!
#endif
	}
	
	public static func createConcurrentQueue(named: String) -> ThreadQueue {
#if USE_LIBDISPATCH
		return dispatch_queue_create(named, DISPATCH_QUEUE_CONCURRENT)
#else
		return 1
#endif
	}
		
	public static func once(inout threadOnce: ThreadOnce, onceFunc: ThreadOnceFunction) {
#if USE_LIBDISPATCH
		dispatch_once(&threadOnce, onceFunc)
#else
		pthread_once(&threadOnce, onceFunc)
#endif
	}
}





