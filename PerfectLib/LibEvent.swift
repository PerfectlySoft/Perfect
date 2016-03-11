//
//  LibEvent.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/5/15.
//	Copyright (C) 2015 PerfectlySoft, Inc.
//
//===----------------------------------------------------------------------===//
//
// This source file is part of the Perfect.org open source project
//
// Copyright (c) 2015 - 2016 PerfectlySoft Inc. and the Perfect project authors
// Licensed under Apache License v2.0
//
// See http://perfect.org/licensing.html for license information
//
//===----------------------------------------------------------------------===//
//

import LibEvent

#if os(Linux)
import SwiftGlibc
#endif

// I'm unsure why these aren't coming through
/** Indicates that a timeout has occurred.  It's not necessary to pass
	this flag to event_for new()/event_assign() to get a timeout. */
let EV_TIMEOUT: Int32 =	0x01
/** Wait for a socket or FD to become readable */
let EV_READ: Int32 =		0x02
/** Wait for a socket or FD to become writeable */
let EV_WRITE: Int32 =	0x04

typealias EventCallBack = (Int32, Int16, AnyObject?) -> ()
private typealias PrimEventCallBack = @convention(c) (Int32, Int16, UnsafeMutablePointer<Void>) -> ()

class LibEvent {
	
	internal static let eventBase: LibEventBase = LibEventBase()
	
	private var event: COpaquePointer? = nil
	private var userData: AnyObject?
	private var cb: EventCallBack?
	private var base: LibEventBase?
	
	private static var eventCallBack: PrimEventCallBack {
		
		let c: PrimEventCallBack = {
			(a,b,c) in
			
			let evt = Unmanaged<LibEvent>.fromOpaque(COpaquePointer(c)).takeRetainedValue()
			let queue = evt.base!.eventDispatchQueue
			let userData: AnyObject? = evt.userData
			let callBack: EventCallBack = evt.cb!
			
			evt.base = nil
			evt.cb = nil
			evt.userData = nil
			
			evt.del()
			
			Threading.dispatchBlock(queue) {
				callBack(a, b, userData)
			}
		}
		
		return c
	}
	
	init(base: LibEventBase, fd: Int32, what: Int32, userData: AnyObject?, callBack: EventCallBack) {
		
		self.userData = userData
		self.cb = callBack
		self.base = base
		self.event = event_new(base.eventBase, fd, Int16(what), LibEvent.eventCallBack, UnsafeMutablePointer(Unmanaged.passRetained(self).toOpaque()))
	}
	
	deinit {
		del()
	}
	
	func add(inout tv: timeval) {
		event_add(event!, &tv)
	}
	
	func add(timeout: Double) {
		if timeout == -1 {
			event_add(event!, nil)
		} else {
			var tv: timeval = timeval()
			let i = floor(timeout)
			let f = timeout - i
			tv.tv_sec = Int(i)
#if os(Linux)
			tv.tv_usec = Int(f * 100000)
#else
			tv.tv_usec = Int32(f * 100000)
#endif
			event_add(event!, &tv)
		}
	}
	
	func add() {
		event_add(event!, nil)
	}
	
	func del() {
		if let e = event {
			event_free(e)
			self.event = nil
		}
	}
}

let EVLOOP_NO_EXIT_ON_EMPTY = Int32(0/*0x04*/) // not supported until libevent 2.1

class LibEventBase {
	
	var eventBase: COpaquePointer
	private var baseDispatchQueue: Threading.ThreadQueue
	var eventDispatchQueue: Threading.ThreadQueue
	
	init() {
		evthread_use_pthreads()
		
		// !FIX! this is not ideal, but since we are the only ones dispatching to this queue, 
		// and it only happens from within the singular libevent loop,  we can ensure is it not called concurrently.
		baseDispatchQueue = Threading.createConcurrentQueue("LibEvent Base") //Threading.createSerialQueue("LibEvent Base")
		eventDispatchQueue = Threading.createConcurrentQueue("LibEvent Event")
		eventBase = event_base_new()
		
		addDummyEvent()
		
		triggerEventBaseLoop()
	}
	
	private func addDummyEvent() {
		let event = LibEvent(base: self, fd: -1, what: EV_TIMEOUT, userData: nil) {
			[weak self] (fd:Int32, w:Int16, ud:AnyObject?) -> () in
			
			self?.addDummyEvent()
		}
		event.add(1_000_000)
	}
	
	private func triggerEventBaseLoop() {
		Threading.dispatchBlock(baseDispatchQueue) { [weak self] in
			self?.eventBaseLoop()
		}
	}
	
	private func eventBaseLoop() {
		let r = event_base_dispatch(self.eventBase) //event_base_loop(self.eventBase, EVLOOP_NO_EXIT_ON_EMPTY)
		if r == 1 {
			triggerEventBaseLoop()
		} else if r == -1 {
			print("eventBaseLoop exited because of error")
		}
	}
}



