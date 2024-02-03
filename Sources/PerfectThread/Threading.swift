//
//  Threading.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2015-12-03.
//  Copyright © 2015 PerfectlySoft. All rights reserved.
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
let CLOCK_MONOTONIC = Int32(1)
#else
import Darwin
#endif

private func my_pthread_cond_timedwait_relative_np(_ cond: UnsafeMutablePointer<pthread_cond_t>,
                                                   _ mutx: UnsafeMutablePointer<pthread_mutex_t>,
                                                   _ tmspec: UnsafePointer<timespec>) -> Int32 {
#if os(Linux)
    var timeout = timespec()
    var time = timeval()
    gettimeofday(&time, nil)
    timeout.tv_sec = time.tv_sec
    timeout.tv_nsec = Int(time.tv_usec) * 1000

    clock_gettime(CLOCK_MONOTONIC, &timeout)
    timeout.tv_sec += tmspec.pointee.tv_sec
    timeout.tv_nsec += tmspec.pointee.tv_nsec
    if timeout.tv_nsec >= 1000000000 {
        timeout.tv_sec += 1
        timeout.tv_nsec -= 1000000000
    }
    let i = pthread_cond_timedwait(cond, mutx, &timeout)
#else
    let i = pthread_cond_timedwait_relative_np(cond, mutx, tmspec)
#endif
	return i
}

/// A wrapper around a variety of threading related functions and classes.
public struct Threading {
    /// Indicates that the call should have no timeout.
	public static let noTimeout = 0.0
	// Non-instantiable.
	private init() {}
	/// The function type which can be given to `Threading.dispatch`.
	public typealias ThreadClosure = () -> ()
}

public extension Threading {
	/// A mutex-type thread lock.
	/// The lock can be held by only one thread. Other threads attempting to secure the lock while it is held will block.
	/// The lock is initialized as being recursive. The locking thread may lock multiple times, but each lock should be accompanied by an unlock.
	class Lock {
		var mutex = pthread_mutex_t()
		/// Initialize a new lock object.
		public init() {
			var attr = pthread_mutexattr_t()
			pthread_mutexattr_init(&attr)
			pthread_mutexattr_settype(&attr, Int32(PTHREAD_MUTEX_RECURSIVE))
			pthread_mutex_init(&mutex, &attr)
		}

		deinit {
			pthread_mutex_destroy(&mutex)
		}

		/// Attempt to grab the lock.
		/// Returns true if the lock was successful.
        @discardableResult
		public func lock() -> Bool {
			return 0 == pthread_mutex_lock(&self.mutex)
		}

		/// Attempt to grab the lock.
		/// Will only return true if the lock was not being held by any other thread.
		/// Returns false if the lock is currently being held by another thread.
		public func tryLock() -> Bool {
			return 0 == pthread_mutex_trylock(&self.mutex)
		}

		/// Unlock. Returns true if the lock was held by the current thread and was successfully unlocked. ior the lock count was decremented.
        @discardableResult
		public func unlock() -> Bool {
			return 0 == pthread_mutex_unlock(&self.mutex)
		}

        /// Acquire the lock, execute the closure, release the lock.
		public func doWithLock<Result>(closure: () throws -> Result) rethrows -> Result {
			_ = self.lock()
			defer {
				_ = self.unlock()
			}
			return try closure()
		}
	}
}

public extension Threading {
	/// A thread event object. Inherits from `Threading.Lock`.
	/// The event MUST be locked before `wait` or `signal` is called.
	/// While inside the `wait` call, the event is automatically placed in the unlocked state.
	/// After `wait` or `signal` return the event will be in the locked state and must be unlocked.
	final class Event: Lock {

		var cond = pthread_cond_t()

		/// Initialize a new Event object.
		override public init() {
			super.init()

			var attr = pthread_condattr_t()
			pthread_condattr_init(&attr)
        #if os (Linux)
			pthread_condattr_setclock(&attr, CLOCK_MONOTONIC)
		#endif
			pthread_cond_init(&cond, &attr)
			pthread_condattr_destroy(&attr)
		}

		deinit {
			pthread_cond_destroy(&cond)
		}

		/// Signal at most ONE thread which may be waiting on this event.
		/// Has no effect if there is no waiting thread.
        @discardableResult
		public func signal() -> Bool {
			return 0 == pthread_cond_signal(&self.cond)
		}

		/// Signal ALL threads which may be waiting on this event.
		/// Has no effect if there is no waiting thread.
        @discardableResult
		public func broadcast() -> Bool {
			return 0 == pthread_cond_broadcast(&self.cond)
		}

		/// Wait on this event for another thread to call signal.
		/// Blocks the calling thread until a signal is received or the timeout occurs.
		/// Returns true only if the signal was received.
		/// Returns false upon timeout or error.
		public func wait(seconds: Double = Threading.noTimeout) -> Bool {
			if seconds == Threading.noTimeout {
				return 0 == pthread_cond_wait(&self.cond, &self.mutex)
			}
			var tm = timespec()
			tm.tv_sec = Int(floor(seconds))
			tm.tv_nsec = (Int(seconds * 1000.0) - (tm.tv_sec * 1000)) * 1000000

			let ret = my_pthread_cond_timedwait_relative_np(&self.cond, &self.mutex, &tm)
			return ret == 0
		}
	}
}

public extension Threading {
	/// A read-write thread lock.
	/// Permits multiple readers to hold the while, while only allowing at most one writer to hold the lock.
	/// For a writer to acquire the lock all readers must have unlocked.
	/// For a reader to acquire the lock no writers must hold the lock.
	final class RWLock {

		var lock = pthread_rwlock_t()

		/// Initialize a new read-write lock.
		public init() {
			pthread_rwlock_init(&self.lock, nil)
		}

		deinit {
			pthread_rwlock_destroy(&self.lock)
		}

		/// Attempt to acquire the lock for reading.
		/// Returns false if an error occurs.
        @discardableResult
		public func readLock() -> Bool {
			return 0 == pthread_rwlock_rdlock(&self.lock)
		}

		/// Attempts to acquire the lock for reading.
		/// Returns false if the lock is held by a writer or an error occurs.
		public func tryReadLock() -> Bool {
			return 0 == pthread_rwlock_tryrdlock(&self.lock)
		}

		/// Attempt to acquire the lock for writing.
		/// Returns false if an error occurs.
        @discardableResult
		public func writeLock() -> Bool {
			return 0 == pthread_rwlock_wrlock(&self.lock)
		}

		/// Attempt to acquire the lock for writing.
		/// Returns false if the lock is held by readers or a writer or an error occurs.
		public func tryWriteLock() -> Bool {
			return 0 == pthread_rwlock_trywrlock(&self.lock)
		}

		/// Unlock a lock which is held for either reading or writing.
		/// Returns false if an error occurs.
        @discardableResult
		public func unlock() -> Bool {
			return 0 == pthread_rwlock_unlock(&self.lock)
		}

        /// Acquire the read lock, execute the closure, release the lock.
		public func doWithReadLock<Result>(closure: () throws -> Result) rethrows -> Result {
			_ = self.readLock()
			defer {
				_ = self.unlock()
			}
			return try closure()
		}

        /// Acquire the write lock, execute the closure, release the lock.
		public func doWithWriteLock<Result>(closure: () throws -> Result) rethrows -> Result {
			_ = self.writeLock()
			defer {
				_ = self.unlock()
			}
			return try closure()
		}
	}
}

public extension Threading {
    /// Block the current thread for the indicated time.
	static func sleep(seconds inSeconds: Double) {
		guard inSeconds >= 0.0 else {
			return
		}
		let milliseconds = Int(inSeconds * 1000.0)
		var tv = timeval()
		tv.tv_sec = milliseconds/1000
#if os(Linux)
		tv.tv_usec = Int((milliseconds%1000)*1000)
#else
		tv.tv_usec = Int32((milliseconds%1000)*1000)
#endif
		select(0, nil, nil, nil, &tv)
	}
}
