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

private let FILT_READ = EPOLLIN.rawValue
private let FILT_WRITE = EPOLLOUT.rawValue
private let FILT_TIMER = EPOLLWAKEUP.rawValue // used as marker, not actually passed into epoll
private let ERROR = EPOLLERR.rawValue
private let FLAG_NONE = 0

#else

import Darwin

private let FILT_READ = EVFILT_READ
private let FILT_WRITE = EVFILT_WRITE
private let FILT_TIMER = EVFILT_TIMER
private let ERROR = EV_ERROR
private let FLAG_NONE = KEVENT_FLAG_NONE

#endif

class NetEvent {

	enum Filter {
		case None, Error(Int32), Read, Write, Timer

		#if os(Linux)
		var epollEvent: UInt32 {
			switch self {
				case .Read:
					return EPOLLIN.rawValue
				case .Write:
					return EPOLLOUT.rawValue
				default:
					return 0
			}
		}
		#else
		var kqueueFilter: Int16 {
			switch self {
			case .Read:
				return Int16(EVFILT_READ)
			case .Write:
				return Int16(EVFILT_WRITE)
			default:
				return 0
			}
		}
		#endif
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
		let associated: SocketType // used for epoll
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

#if os(Linux)
				let nev = Int(epoll_wait(self.kq, self.evlist, Int32(self.numEvents), -1))
#else
				let nev = Int(kevent(self.kq, nil, 0, self.evlist, Int32(self.numEvents), nil))
#endif
				guard nev >= 0 else {
					Log.terminal("kqueue returned less than zero \(nev).")
				}

				// process results
				self.lock.doWithLock {

					for n in 0..<nev {
						let evt = self.evlist[n]
#if os(Linux)
						let sock = SocketType(evt.data.fd)
						var filter = Filter.None
						if (evt.events & EPOLLERR.rawValue) != 0 {
							var errData = Int32(0)
							var errLen = socklen_t(sizeof(Int32))
							getsockopt(sock, SOL_SOCKET, SO_ERROR, &errData, &errLen)
							filter = .Error(errData)
						} else if (evt.events & EPOLLIN.rawValue) != 0 {
							filter = .Read
						} else if (evt.events & EPOLLOUT.rawValue) != 0 {
							filter = .Write
						}
#else
						let sock = SocketType(evt.ident)
						var filter = Filter.None
						if evt.filter == Int16(EV_ERROR) {
							filter = .Error(Int32(evt.data))
						} else if evt.filter == Int16(EVFILT_READ) {
							filter = .Read
						} else if evt.filter == Int16(EVFILT_WRITE) {
							filter = .Write
						}
#endif
						if let qitm = self.queuedSockets.removeValue(forKey: sock) {
							qitm.callback(sock, filter)
						} else {
							print("not found!")
						}
					}
				}
			}
		}
	}

	// socket can only be queued with one callback at a time
	static func add(socket: SocketType, what: Filter, timeoutSeconds: Double, callback: EventCallback) {

		let threadingCallback:EventCallback = {
			s, f in
			Threading.dispatchBlock {
				callback(s, f)
			}
		}

		if let n = NetEvent.staticEvent {

			n.lock.doWithLock {
				n.queuedSockets[socket] = QueuedSocket(socket: socket, what: what, timeoutSeconds: timeoutSeconds < 0.0 ? noTimeout : timeoutSeconds, callback: threadingCallback, associated: 0)
#if os(Linux)
				var evt = event()
				evt.events = what.epollEvent | EPOLLONESHOT.rawValue | EPOLLET.rawValue
				evt.data.fd = socket
				epoll_ctl(n.kq, EPOLL_CTL_ADD, socket, &evt)
#else
				var kvt = event(ident: UInt(socket), filter: what.kqueueFilter, flags: UInt16(EV_ADD | EV_ENABLE | EV_ONESHOT), fflags: 0, data: 0, udata: nil)
				var tmout = timespec(tv_sec: 0, tv_nsec: 0)
				kevent(n.kq, &kvt, 1, nil, 0, &tmout)
#endif
			}
		}
	}

	static func remove(socket: SocketType) {
		if let n = NetEvent.staticEvent {
			n.lock.doWithLock {
				if let _ = n.queuedSockets[socket] {
#if os(Linux)
					epoll_ctl(n.kq, EPOLL_CTL_DEL, socket, nil)
#else
					var kvt = event(ident: UInt(socket), filter: Int16(EV_DELETE), flags: UInt16(EV_DELETE), fflags: 0, data: 0, udata: nil)
					var tmout = timespec(tv_sec: 0, tv_nsec: 0)
					kevent(n.kq, &kvt, 1, nil, 0, &tmout)
#endif
					n.queuedSockets.removeValue(forKey: socket)
				}
			}
		}
	}
}
