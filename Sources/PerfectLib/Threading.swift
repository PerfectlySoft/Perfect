//
//  Threading.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2015-12-03.
//  Copyright © 2015 PerfectlySoft. All rights reserved.
//

#if os(Linux)
import SwiftGlibc
import LinuxBridge
let CLOCK_MONOTONIC = Int32(1)
#else
import Darwin
#endif

/// A wrapper around a variety of threading related functions and classes.
public struct Threading {

	public static var noTimeout = 0.0
	
	/// Non-instantiable.
	private init() {}

	/// The function type which can be given to `Threading.once`.
	public typealias ThreadOnceFunction = @convention(c) () -> ()
	/// The function type which can be given to `Threading.dispatch`.
	public typealias ThreadClosure = () -> ()

	/// The key type used for `Threading.once`.
	public typealias ThreadOnce = pthread_once_t
	#if swift(>=3.0)
	typealias VoidPointer = UnsafeMutablePointer<Void>?
	#else
	typealias VoidPointer = UnsafeMutablePointer<Void>
	#endif
	typealias ThreadFunction = @convention(c) (VoidPointer) -> VoidPointer
	
	final class IsThisRequired {
		let closure: ThreadClosure
		init(closure: ThreadClosure) {
			self.closure = closure
		}
	}

	/// A mutex-type thread lock.
	/// The lock can be held by only one thread. Other threads attempting to secure the lock while it is held will block.
	/// The lock is initialized as being recursive. The locking thread may lock multiple times, but each lock should be accompanied by an unlock.
	public class Lock {

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
		public func unlock() -> Bool {
			return 0 == pthread_mutex_unlock(&self.mutex)
		}

		public func doWithLock(closure: () throws -> ()) rethrows {
			let _ = self.lock()
			defer {
				let _ = self.unlock()
			}
			try closure()
		}
	}

	/// A thread event object. Inherits from `Threading.Lock`.
	/// The event MUST be locked before `wait` or `signal` is called.
	/// While inside the `wait` call, the event is automatically placed in the unlocked state.
	/// After `wait` or `signal` return the event will be in the locked state and must be unlocked.
	public final class Event: Lock {

		var cond = pthread_cond_t()

		/// Initialize a new Event object.
		override init() {
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
		public func signal() -> Bool {
			return 0 == pthread_cond_signal(&self.cond)
		}

		/// Signal ALL threads which may be waiting on this event.
		/// Has no effect if there is no waiting thread.
		public func broadcast() -> Bool {
			return 0 == pthread_cond_broadcast(&self.cond)
		}

		/// Wait on this event for another thread to call signal.
		/// Blocks the calling thread until a signal is received or the timeout occurs.
		/// Returns true only if the signal was received.
		/// Returns false upon timeout or error.
		public func wait(seconds secs: Double = Threading.noTimeout) -> Bool {
			if secs == Threading.noTimeout {
				return 0 == pthread_cond_wait(&self.cond, &self.mutex)
			}
			let waitMillis = Int(secs * 1000.0)
			var tm = timespec()
			tm.tv_sec = waitMillis / 1000
			tm.tv_nsec = (waitMillis - (tm.tv_sec * 1000)) * 1000000

			let ret = pthread_cond_timedwait_relative_np(&self.cond, &self.mutex, &tm)

			return ret == 0;
		}
	}

	/// A read-write thread lock.
	/// Permits multiple readers to hold the while, while only allowing at most one writer to hold the lock.
	/// For a writer to acquire the lock all readers must have unlocked.
	/// For a reader to acquire the lock no writers must hold the lock.
	public final class RWLock {

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
		public func unlock() -> Bool {
			return 0 == pthread_rwlock_unlock(&self.lock)
		}
		
		public func doWithReadLock(closure: () throws -> ()) rethrows {
			let _ = self.readLock()
			defer {
				let _ = self.unlock()
			}
			try closure()
		}
		
		public func doWithWriteLock(closure: () throws -> ()) rethrows {
			let _ = self.writeLock()
			defer {
				let _ = self.unlock()
			}
			try closure()
		}
	}

	/// Call the provided closure on the current thread, but only if it has not been called before.
	/// This is useful for ensuring that initialization code is only called once in a multi-threaded process.
	/// Upon returning from `Threading.once` it is guaranteed that the closure has been executed and has completed.
	#if swift(>=3.0)
	public static func once(_ threadOnce: inout ThreadOnce, onceFunc: ThreadOnceFunction) {
		pthread_once(&threadOnce, onceFunc)
	}
	#else
	public static func once(inout threadOnce: ThreadOnce, onceFunc: ThreadOnceFunction) {
		pthread_once(&threadOnce, onceFunc)
	}
	#endif

	public static func sleep(seconds inSeconds: Double) {
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
