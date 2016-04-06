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
	private var changedSockets = [SocketType:QueuedSocket]()
	
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
			Threading.dispatchBlock {
				NetEvent.staticEvent = NetEvent()
				NetEvent.staticEvent.runLoop()
			}
		}
	}
	
	private func runLoop() {
		
		var idx = 0
		while true {
			// process changes
			self.lock.doWithLock {
				
				for (key, value) in self.changedSockets {
					if idx + 2 > self.numEvents {
						self.growLists()
					}
					if value.what == .Delete {
						if let found = self.queuedSockets[key] {
							let kvt = mykevent(ident: UInt(key), filter: found.what.rawValue, flags: UInt16(EV_DELETE), fflags: 0, data: 0, udata: nil)
							self.chlist[idx] = kvt
							idx += 1
							self.queuedSockets.removeValue(forKey: key)
						}
					} else {
						self.queuedSockets[key] = value
						if value.what != .Timer {
							
							print("adding for sock: \(key) what: \(value.what.rawValue) timeout: \(value.timeoutSeconds)")
							
							let kvt = mykevent(ident: UInt(key), filter: value.what.rawValue, flags: UInt16(EV_ADD | EV_ONESHOT), fflags: 0, data: 0, udata: nil)
							self.chlist[idx] = kvt
							idx += 1
						}
						if value.what == .Timer || value.timeoutSeconds != NetEvent.noTimeout {
							let kvt = mykevent(ident: UInt(key), filter: Int16(EVFILT_TIMER), flags: UInt16(EV_ADD | EV_ONESHOT), fflags: 0, data: Int(1000.0 * value.timeoutSeconds), udata: nil)
							self.chlist[idx] = kvt
							idx += 1
						}
					}
				}
				self.changedSockets.removeAll()
			}
			
			var tmout = timespec(tv_sec: 0, tv_nsec: 10)
			let nev = Int(kevent(kq, chlist, Int32(idx), evlist, Int32(numEvents), &tmout))
			
			idx = 0
			
			guard self.kq != -1 else {
				Log.terminal("kqueue returned less than zero \(nev).")
			}
			
			// process results
			self.lock.doWithLock {
				
				for n in 0..<nev {
					let kevt = self.evlist[n]
					let sock = SocketType(kevt.ident)
					if let qitm = self.queuedSockets.removeValue(forKey: sock) {
						
						Log.info("kevent result sock: \(kevt.ident) filter: \(kevt.filter) flags: \(kevt.flags) data: \(kevt.data)")
						
						if kevt.filter == Int16(EVFILT_TIMER) && qitm.what != .Timer {
							let kvt = mykevent(ident: kevt.ident, filter: qitm.what.rawValue, flags: UInt16(EV_DELETE), fflags: 0, data: 0, udata: nil)
							self.chlist[idx] = kvt
							idx += 1
						} else if kevt.filter != Int16(EVFILT_TIMER) && qitm.timeoutSeconds != NetEvent.noTimeout {
							let kvt = mykevent(ident: kevt.ident, filter: Int16(EVFILT_TIMER), flags: UInt16(EV_DELETE), fflags: 0, data: 0, udata: nil)
							self.chlist[idx] = kvt
							idx += 1
						}
						
						if (Int32(kevt.flags) & EV_ERROR) != 0 {
							qitm.callback(sock, Filter(rawValue: Filter.Error.rawValue, data: kevt.data))
						} else {
							qitm.callback(sock, Filter(rawValue: kevt.filter))
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
			n.lock.doWithLock {
				var newWhat = what
				if let found = n.changedSockets[socket] {
					// augment the event or clear it out if it was a delete
					if what == .Delete {
						newWhat = .Delete
					} else {
						newWhat = newWhat.union(found.what)
					}
				}
				n.changedSockets[socket] = QueuedSocket(socket: socket, what: what, timeoutSeconds: timeoutSeconds < 0.0 ? noTimeout : timeoutSeconds, callback: threadingCallback)
			}
		}
	}
	
	static func remove(socket: SocketType) {
		if let n = NetEvent.staticEvent {
			n.lock.doWithLock {
				if let _ = n.queuedSockets[socket] {
					n.changedSockets[socket] = QueuedSocket(socket: socket, what: .Delete, timeoutSeconds: 0.0, callback: NetEvent.emptyCallback)
				}
			}
		}
	}
	
	
}






