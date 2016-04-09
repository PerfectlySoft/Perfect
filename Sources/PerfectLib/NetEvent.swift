//
//  NetEvent.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2016-04-04.
//  Copyright © 2016 PerfectlySoft. All rights reserved.
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

#if os(Linux)
	
#else
	import Darwin
#endif

class NetEvent {
	
	struct Filter: OptionSet {
		let rawValue: Int16
		let data: Int
		init(rawValue: Int16) {
			self.rawValue = rawValue
			self.data = 0
		}
		
		init(rawValue: Int16, data: Int) {
			self.rawValue = rawValue
			self.data = data
		}
		
		func isTimeout() -> Bool {
			return self == .Timer
		}
		
		static let None = Filter(rawValue: Int16(KEVENT_FLAG_NONE))
		static let Error = Filter(rawValue: Int16(EV_ERROR))
		static let Delete = Filter(rawValue: Int16(EV_DELETE))
		static let Read = Filter(rawValue: Int16(EVFILT_READ))
		static let Write = Filter(rawValue: Int16(EVFILT_WRITE))
		static let Timer = Filter(rawValue: Int16(EVFILT_TIMER))
	}
	
	typealias EventCallback = (SocketType, Filter) -> ()
	private static let emptyCallback:EventCallback = { (SocketType, Filter) -> () in }
	
	private typealias mykevent = kevent
	
	private struct QueuedSocket {
		let socket: SocketType
		let what: Filter
		let timeoutSeconds: Double
		let callback: EventCallback
	}
	
	private static var staticEvent: NetEvent!
	
	private let kq: Int32
	private let lock = Threading.Lock()
	private var queuedSockets = [SocketType:QueuedSocket]()
	
	private var numEvents = 64
	private var chlist: UnsafeMutablePointer<mykevent>
	private var evlist: UnsafeMutablePointer<mykevent>
	
	private static var initOnce = Threading.ThreadOnce()
	
	static let noTimeout = 0.0
	
	private init() {
		self.kq = kqueue()
		guard self.kq != -1 else {
			Log.terminal("Unable to initialize kqueue.")
		}
		
		self.chlist = UnsafeMutablePointer<mykevent>(allocatingCapacity: self.numEvents)
		self.evlist = UnsafeMutablePointer<mykevent>(allocatingCapacity: self.numEvents)
		
		memset(self.chlist, 0, sizeof(kevent.self) * self.numEvents)
		memset(self.evlist, 0, sizeof(kevent.self) * self.numEvents)
	}
	
	static func initialize() {
		Threading.once(&NetEvent.initOnce) {
			NetEvent.staticEvent = NetEvent()
			NetEvent.staticEvent.runLoop()
		}
	}
	
	private func runLoop() {
		
		let q = Threading.getQueue("NetEvent", type: .Serial)
		q.dispatch {
			var idx = 0
			while true {
				
	//			let inTime = ICU.getNow()
				let nev = Int(kevent(self.kq, self.chlist, Int32(idx), self.evlist, Int32(self.numEvents), nil))
	//			print("Out of kqueue \(nev) \(ICU.getNow() - inTime)")
				
				idx = 0
				
				guard self.kq != -1 else {
					Log.terminal("kqueue returned less than zero \(nev).")
				}
				
				// process results
				self.lock.doWithLock {
					
					for n in 0..<nev {
						let kevt = self.evlist[n]
						let sock = SocketType(kevt.ident)
						
	//					Log.info("kevent result sock: \(kevt.ident) filter: \(kevt.filter) flags: \(kevt.flags) data: \(kevt.data)")
						
						if let qitm = self.queuedSockets.removeValue(forKey: sock) {
							
							if idx + 1 > self.numEvents {
								self.growLists()
							}
							
							if (Int32(kevt.flags) & EV_ERROR) != 0 {
								qitm.callback(sock, Filter(rawValue: Filter.Error.rawValue, data: kevt.data))
							} else {
								qitm.callback(sock, Filter(rawValue: kevt.filter))
							}
						} else {
							print("not found!")
						}
					}
					
				}
			}
		}
	}
	
	private func growLists() {
		let newSz = self.numEvents * 2
		
		let chlist = UnsafeMutablePointer<mykevent>(allocatingCapacity: newSz)
		let evlist = UnsafeMutablePointer<mykevent>(allocatingCapacity: newSz)
		
		memset(chlist, 0, sizeof(mykevent) * newSz)
		memset(evlist, 0, sizeof(mykevent) * newSz)
		
		chlist.initializeFrom(self.chlist, count: self.numEvents)
		evlist.initializeFrom(self.evlist, count: self.numEvents)
		
		self.chlist.deallocateCapacity(self.numEvents)
		self.evlist.deallocateCapacity(self.numEvents)
		
		self.chlist = chlist
		self.evlist = evlist
		
		self.numEvents = newSz
	}
	
	// socket can only be queued with one callback at a time
	// but can be waiting for multiple event types
	//
	static func add(socket: SocketType, what: Filter, timeoutSeconds: Double, callback: EventCallback) {
		
		let threadingCallback:EventCallback = {
			s, f in
			Threading.dispatchBlock {
				callback(s, f)
			}
		}
		
		if let n = NetEvent.staticEvent {
			if what == .Delete {
				NetEvent.remove(socket)
			} else {
				n.lock.doWithLock {
					n.queuedSockets[socket] = QueuedSocket(socket: socket, what: what, timeoutSeconds: timeoutSeconds < 0.0 ? noTimeout : timeoutSeconds, callback: threadingCallback)
					var kvt = mykevent(ident: UInt(socket), filter: what.rawValue, flags: UInt16(EV_ADD | EV_ENABLE | EV_ONESHOT), fflags: 0, data: 0, udata: nil)
					var tmout = timespec(tv_sec: 0, tv_nsec: 0)
					kevent(n.kq, &kvt, 1, nil, 0, &tmout)
				}
			}
		}
	}
	
	static func remove(socket: SocketType) {
		if let n = NetEvent.staticEvent {
			n.lock.doWithLock {
				if let _ = n.queuedSockets[socket] {
					var kvt = mykevent(ident: UInt(socket), filter: Filter.Delete.rawValue, flags: UInt16(EV_DELETE), fflags: 0, data: 0, udata: nil)
					var tmout = timespec(tv_sec: 0, tv_nsec: 0)
					kevent(n.kq, &kvt, 1, nil, 0, &tmout)
					n.queuedSockets.removeValue(forKey: socket)
				}
			}
		}
	}
	
	
	
	static func removeOnClose(socket: SocketType) {
		
	}
}






