//
//  LibEvent.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/5/15.
//	Copyright (C) 2015 PerfectlySoft, Inc.
//
//     This program is free software: you can redistribute it and/or modify
//     it under the terms of the GNU Affero General Public License as published by
//     the Free Software Foundation, either version 3 of the License, or
//     (at your option) any later version.
//
//     This program is distributed in the hope that it will be useful,
//     but WITHOUT ANY WARRANTY; without even the implied warranty of
//     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//     GNU Affero General Public License for more details.
//
//     You should have received a copy of the GNU Affero General Public License
//     along with this program.  If not, see <http://www.gnu.org/licenses/>.
//


import Foundation
import LibEvent

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
			
			dispatch_async(queue) {
				callBack(a, b, userData)
			}
		}
		
		return c
	}
	
	init(base: LibEventBase, fd: Int32, what: Int32, userData: AnyObject?, callBack: EventCallBack) {
		
		self.userData = userData
		self.cb = callBack
		self.base = base
		event = event_new(base.eventBase, fd, Int16(what), LibEvent.eventCallBack, UnsafeMutablePointer(Unmanaged.passRetained(self).toOpaque()))
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
			tv.tv_sec = __darwin_time_t(i)
			tv.tv_usec = __darwin_suseconds_t(f * 100000)
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
	private var baseDispatchQueue: dispatch_queue_t
	var eventDispatchQueue: dispatch_queue_t
	
	init() {
		evthread_use_pthreads()
		
		baseDispatchQueue = dispatch_queue_create("LibEvent Base", DISPATCH_QUEUE_SERIAL)
		eventDispatchQueue = dispatch_queue_create("LibEvent Event", DISPATCH_QUEUE_CONCURRENT)
		eventBase = event_base_new()
		
		addDummyEvent()
		
		triggerEventBaseLoop()
	}
	
	private func addDummyEvent() {
		let event = LibEvent(base: self, fd: -1, what: EV_TIMEOUT, userData: nil) {
			(fd:Int32, w:Int16, ud:AnyObject?) -> () in
			
			self.addDummyEvent()
		}
		event.add(1_000_000)
	}
	
	private func triggerEventBaseLoop() {
		dispatch_async(baseDispatchQueue) {
			self.eventBaseLoop()
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



