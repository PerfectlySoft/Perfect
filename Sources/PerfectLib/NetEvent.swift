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

import LinuxBridge

private let ONESHOT = EPOLLONESHOT.rawValue
private let ADD = EPOLL_CTL_ADD
private let DELETE = EPOLL_CTL_DEL
private let FILT_READ = EPOLLIN.rawValue
private let FILT_WRITE = EPOLLOUT.rawValue
private let FILT_TIMER = EPOLLWAKEUP.rawValue // used as marker, not actually passed into epoll
private let ERROR = EPOLLERR.rawValue
private let FLAG_NONE = 0

#else

import Darwin

private let ONESHOT = EPOLLONESHOT
private let ADD = EV_ADD
private let DELETE = EV_DELETE
private let FILT_READ = EVFILT_READ
private let FILT_WRITE = EVFILT_WRITE
private let FILT_TIMER = EVFILT_TIMER
private let ERROR = EV_ERROR
private let FLAG_NONE = KEVENT_FLAG_NONE

#endif

class NetEvent {

	struct Filter: OptionSet {
		let rawValue: UInt32
		let data: Int
		init(rawValue: UInt32) {
			self.rawValue = rawValue
			self.data = 0
		}

		init(rawValue: UInt32, data: Int) {
			self.rawValue = rawValue
			self.data = data
		}

		func isTimeout() -> Bool {
			return self == .Timer
		}

		static let None = Filter(rawValue: UInt32(FLAG_NONE))
		static let Error = Filter(rawValue: UInt32(ERROR))
		static let Delete = Filter(rawValue: UInt32(DELETE))
		static let Read = Filter(rawValue: UInt32(FILT_READ))
		static let Write = Filter(rawValue: UInt32(FILT_WRITE))
		static let Timer = Filter(rawValue: UInt32(FILT_TIMER))
	}

	typealias EventCallback = (SocketType, Filter) -> ()
	private static let emptyCallback:EventCallback = { (SocketType, Filter) -> () in }

#if os(Linux)
	private typealias event = epoll_event
#else
	private typealias event = kevent
#endif

	private struct QueuedSocket {
		let socket: SocketType
		let what: Filter
		let timeoutSeconds: Double
		let callback: EventCallback
		let associated: SocketType // unused for kevent
	}

	private static var staticEvent: NetEvent!

	private let kq: Int32
	private let lock = Threading.Lock()
	private var queuedSockets = [SocketType:QueuedSocket]()

	private var numEvents = 64
	private var evlist: UnsafeMutablePointer<event>

	private static var initOnce = Threading.ThreadOnce()

	static let noTimeout = 0.0

	private init() {
#if os(Linux)
		self.kq = epoll_create(0xFEC7)
#else
		self.kq = kqueue()
#endif
		guard self.kq != -1 else {
			Log.terminal("Unable to initialize event listener.")
		}
		self.evlist = UnsafeMutablePointer<event>(allocatingCapacity: self.numEvents)
		memset(self.evlist, 0, sizeof(event.self) * self.numEvents)
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
			while true {
	//			let inTime = ICU.getNow()
#if os(Linux)
				let nev = Int(epoll_wait(self.kq, self.evlist, Int32(self.numEvents), -1))
#else
				let nev = Int(kevent(self.kq, nil, 0, self.evlist, Int32(self.numEvents), nil))
#endif
	//			print("Out of kqueue \(nev) \(ICU.getNow() - inTime)")

				guard nev >= 0 else {
					Log.terminal("kqueue returned less than zero \(nev).")
				}

				// process results
				self.lock.doWithLock {

					for n in 0..<nev {
						let evt = self.evlist[n]
#if os(Linux)
						let sock = SocketType(evt.data.fd)
						let filter = evt.events
						let error = (evt.events & ERROR) != 0

						var errData = Int32(0)
						if error {
							var errLen = socklen_t(sizeof(Int32))
							getsockopt(sock, SOL_SOCKET, SO_ERROR, &errData, &errLen)
						}
#else
						let sock = SocketType(evt.ident)
						let filter = evt.filter
						let error = (evt.flags & ERROR) != 0
						let errData = evt.data
#endif
	//					Log.info("kevent result sock: \(kevt.ident) filter: \(kevt.filter) flags: \(kevt.flags) data: \(kevt.data)")

						if let qitm = self.queuedSockets.removeValue(forKey: sock) {
							if error {
								qitm.callback(sock, Filter(rawValue: Filter.Error.rawValue, data: Int(errData)))
							} else {
								qitm.callback(sock, Filter(rawValue: filter))
							}
						} else {
							print("not found!")
						}
					}
				}
			}
		}
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
					n.queuedSockets[socket] = QueuedSocket(socket: socket, what: what, timeoutSeconds: timeoutSeconds < 0.0 ? noTimeout : timeoutSeconds, callback: threadingCallback, associated: 0)
#if os(Linux)
					var evt = event()
					evt.events = what.rawValue | ONESHOT | EPOLLET.rawValue
					evt.data.fd = socket
					epoll_ctl(n.kq, ADD, socket, &evt)
#else
					var kvt = event(ident: UInt(socket), filter: what.rawValue, flags: UInt16(EV_ADD | EV_ENABLE | EV_ONESHOT), fflags: 0, data: 0, udata: nil)
					var tmout = timespec(tv_sec: 0, tv_nsec: 0)
					kevent(n.kq, &kvt, 1, nil, 0, &tmout)
#endif
				}
			}
		}
	}

	static func remove(socket: SocketType) {
		if let n = NetEvent.staticEvent {
			n.lock.doWithLock {
				if let _ = n.queuedSockets[socket] {
#if os(Linux)
					epoll_ctl(n.kq, DELETE, socket, nil)
#else
					var kvt = mykevent(ident: UInt(socket), filter: Filter.Delete.rawValue, flags: UInt16(EV_DELETE), fflags: 0, data: 0, udata: nil)
					var tmout = timespec(tv_sec: 0, tv_nsec: 0)
					kevent(n.kq, &kvt, 1, nil, 0, &tmout)
#endif
					n.queuedSockets.removeValue(forKey: socket)
				}
			}
		}
	}



	static func removeOnClose(socket: SocketType) {

	}
}
