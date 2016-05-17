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

import SwiftGlibc
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

	private static let debug = false

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

	static let noTimeout = Threading.noTimeout

	private init() {

		var sa = sigaction()

#if os(Linux)
		self.kq = epoll_create(0xFEC7)
		sa.__sigaction_handler.sa_handler = SIG_IGN
#else
		self.kq = kqueue()
		sa.__sigaction_u.__sa_handler = SIG_IGN
#endif

		sa.sa_flags = 0
		sigaction(SIGPIPE, &sa, nil)

		guard self.kq != -1 else {
			Log.terminal(message: "Unable to initialize event listener.")
		}
		self.evlist = UnsafeMutablePointer<event>.allocatingCapacity(self.numEvents)
		memset(self.evlist, 0, sizeof(event.self) * self.numEvents)
	}

	static func initialize() {
		Threading.once(&NetEvent.initOnce) {
			NetEvent.staticEvent = NetEvent()
			NetEvent.staticEvent.runLoop()
		}
	}

	private func runLoop() {

		let q = Threading.getQueue(name: "NetEvent", type: .Serial)
		q.dispatch {
			while true {
//				print("event wait")
#if os(Linux)
				let nev = Int(epoll_wait(self.kq, self.evlist, Int32(self.numEvents), -1))
#else
				let nev = Int(kevent(self.kq, nil, 0, self.evlist, Int32(self.numEvents), nil))
#endif
				guard nev >= 0 else {
					Log.terminal(message: "event returned less than zero \(nev).")
				}
				// process results
				self.lock.doWithLock {
					if NetEvent.debug {
						print("event wait returned \(nev)")
					}
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
//						print("event rcv \(sock) \(evt.events)")
#else
						let sock = SocketType(evt.ident)
						var filter = Filter.None
						if evt.filter == Int16(EVFILT_TIMER) {
							filter = .Timer
						} else if evt.filter == Int16(EV_ERROR) {
							filter = .Error(Int32(evt.data))
						} else if evt.filter == Int16(EVFILT_READ) {
							filter = .Read
						} else if evt.filter == Int16(EVFILT_WRITE) {
							filter = .Write
						}
						if NetEvent.debug {
							print("event rcv \(sock) \(filter) \(evt.data)")
						}
#endif
						if let qitm = self.queuedSockets.removeValue(forKey: sock) {
#if os(Linux)
							epoll_ctl(self.kq, EPOLL_CTL_DEL, sock, nil)
#else
							if qitm.timeoutSeconds > NetEvent.noTimeout {
								// need to either remove the timer or the failed event
								// this could be optimised to do all removes at once
								var tmout = timespec(tv_sec: 0, tv_nsec: 0)
								if case .Timer = filter {
									if NetEvent.debug {
										print("event del \(sock) \(qitm.what)")
									}
									var kvt = event(ident: UInt(sock), filter: qitm.what.kqueueFilter, flags: UInt16(EV_DELETE), fflags: 0, data: 0, udata: nil)
									kevent(self.kq, &kvt, 1, nil, 0, &tmout)
								} else {
									if NetEvent.debug {
										print("event del \(sock) EVFILT_TIMER")
									}
									var kvt = event(ident: UInt(sock), filter: Int16(EVFILT_TIMER), flags: UInt16(EV_DELETE), fflags: 0, data: 0, udata: nil)
									kevent(self.kq, &kvt, 1, nil, 0, &tmout)
								}
							}
#endif
							qitm.callback(sock, filter)
						} else {
#if os(Linux)
							print("event socket not found \(sock) \(evt.events)")
#else
							if NetEvent.debug {
								print("event socket not found \(sock) \(evt.filter)")
							}
#endif
						}
					}
				}
			}
		}
	}

	// socket can only be queued with one callback at a time
	static func add(socket newSocket: SocketType, what: Filter, timeoutSeconds: Double, callback: EventCallback) {
		let threadingCallback:EventCallback = {
			s, f in
			Threading.dispatch {
				callback(s, f)
			}
		}

		if let n = NetEvent.staticEvent {

			n.lock.doWithLock {
				n.queuedSockets[newSocket] = QueuedSocket(socket: newSocket, what: what, timeoutSeconds: timeoutSeconds, callback: threadingCallback, associated: 0)
#if os(Linux)
				var evt = event()
				evt.events = what.epollEvent | EPOLLONESHOT.rawValue | EPOLLET.rawValue
				evt.data.fd = newSocket
				epoll_ctl(n.kq, EPOLL_CTL_ADD, newSocket, &evt)

//				print("event add \(socket) \(evt.events)")
#else
				var tmout = timespec(tv_sec: 0, tv_nsec: 0)
				if timeoutSeconds > noTimeout {
					var kvt = event(ident: UInt(newSocket), filter: Int16(EVFILT_TIMER), flags: UInt16(EV_ADD | EV_ENABLE | EV_ONESHOT), fflags: 0, data: Int(timeoutSeconds * 1000), udata: nil)
					kevent(n.kq, &kvt, 1, nil, 0, &tmout)
					if NetEvent.debug {
						print("event add \(newSocket) EVFILT_TIMER")
					}
				}
				var kvt = event(ident: UInt(newSocket), filter: what.kqueueFilter, flags: UInt16(EV_ADD | EV_ENABLE | EV_ONESHOT), fflags: 0, data: 0, udata: nil)
				kevent(n.kq, &kvt, 1, nil, 0, &tmout)
				if NetEvent.debug {
					print("event add \(newSocket) \(what.kqueueFilter)")
				}
#endif
			}
		}
	}

	static func remove(socket oldSocket: SocketType) {
		if let n = NetEvent.staticEvent {
			n.lock.doWithLock {
				if let old = n.queuedSockets[oldSocket] {
#if os(Linux)
					epoll_ctl(n.kq, EPOLL_CTL_DEL, oldSocket, nil)
#else
					// ensure any associate timer is deleted
					// these two calls could be conglomerated but would require allocation. revisit
					var kvt = event(ident: UInt(oldSocket), filter: old.what.kqueueFilter, flags: UInt16(EV_DELETE), fflags: 0, data: 0, udata: nil)
					var tmout = timespec(tv_sec: 0, tv_nsec: 0)
					kevent(n.kq, &kvt, 1, nil, 0, &tmout)
					if old.timeoutSeconds > noTimeout {
						kvt = event(ident: UInt(oldSocket), filter: Int16(EVFILT_TIMER), flags: UInt16(EV_DELETE), fflags: 0, data: 0, udata: nil)
						kevent(n.kq, &kvt, 1, nil, 0, &tmout)
					}
#endif
					n.queuedSockets.removeValue(forKey: oldSocket)
				}
			}
		}
	}
}
