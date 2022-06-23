//
//  NetEvent.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2016-04-04.
//  Copyright © 2016 PerfectlySoft. All rights reserved.
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

import PerfectThread
import Dispatch

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

func logTerminal(message: String) -> Never  {
    print(message)
    exit(-1)
}

private let netEventQueue = DispatchQueue(label: "NetEvent")
private let netManageQueue = DispatchQueue(label: "NetManage")
public let netHandleQueue = DispatchQueue(label: "NetHandle",
										   qos: .userInitiated,
										   attributes: .concurrent)

public class NetEvent {
	public enum Filter {
		case none, error(Int32), read, write, timer
    #if os(Linux)
		var epollEvent: UInt32 {
			switch self {
			case .read:
				return EPOLLIN.rawValue
			case .write:
				return EPOLLOUT.rawValue
			default:
				return 0
			}
		}
    #else
		var kqueueFilter: Int16 {
			switch self {
			case .read:
				return Int16(EVFILT_READ)
			case .write:
				return Int16(EVFILT_WRITE)
			default:
				return 0
			}
		}
    #endif
	}

	public typealias EventCallback = (SocketType, Filter) -> ()
	private static let emptyCallback: EventCallback = { _, _ in }

#if os(Linux)
    // swiftlint:disable type_name
	private typealias event = epoll_event
#else
    // swiftlint:disable type_name
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
	private var queuedSockets = [SocketType: QueuedSocket]()

	private var numEvents = 64
	private var evlist: UnsafeMutablePointer<event>

	private static var initOnce: Bool = {
		NetEvent.staticEvent = NetEvent()
		NetEvent.staticEvent.runLoop()
		return true
	}()

	public static let noTimeout = Threading.noTimeout

	private init() {
		var sa = sigaction()
	#if os(Linux)
		kq = epoll_create(0xFEC7)
		sa.__sigaction_handler.sa_handler = SIG_IGN
	#else
		kq = kqueue()
		sa.__sigaction_u.__sa_handler = SIG_IGN
	#endif
		sa.sa_flags = 0
		sigaction(SIGPIPE, &sa, nil)
		var rlmt = rlimit()
	#if os(Linux)
		getrlimit(Int32(RLIMIT_NOFILE.rawValue), &rlmt)
		rlmt.rlim_cur = rlmt.rlim_max
		setrlimit(Int32(RLIMIT_NOFILE.rawValue), &rlmt)
	#else
		getrlimit(RLIMIT_NOFILE, &rlmt)
		rlmt.rlim_cur = rlim_t(OPEN_MAX)
		setrlimit(RLIMIT_NOFILE, &rlmt)
	#endif
		guard kq != -1 else {
			logTerminal(message: "Unable to initialize event listener.")
		}
		evlist = UnsafeMutablePointer<event>.allocate(capacity: numEvents)
		memset(evlist, 0, MemoryLayout<event>.size * numEvents)
	}

	public static func initialize() {
		_ = NetEvent.initOnce
	}

	private func runLoop() {
		netEventQueue.async { self.loop() }
	}
	private func loop() {
		while true {
		#if os(Linux)
			var nev = Int(epoll_wait(kq, evlist, Int32(numEvents), -1))
		#else
			var nev = Int(kevent(kq, nil, 0, evlist, Int32(numEvents), nil))
		#endif
			if nev == -1 {
				if errno == EINTR {
					nev = 0
				} else {
					logTerminal(message: "event returned less than zero \(nev) \(errno).")
				}
			}
			// process results
			do {
				_ = lock.lock()
				defer {
					_ = lock.unlock()
				}
				if NetEvent.debug {
					print("event wait returned \(nev)")
				}
				for n in 0..<nev {
					let evt = evlist[n]
				#if os(Linux)
					let sock = SocketType(evt.data.fd)
				#else
					let sock = SocketType(evt.ident)
				#endif
					guard let qitm = queuedSockets.removeValue(forKey: sock) else {
						if NetEvent.debug {
					#if os(Linux)
							print("event socket not found \(sock) \(evt.events)")
					#else
							print("event socket not found \(sock) \(evt.filter)")
					#endif
						}
						continue
					}

					let qitmIsTimeout = qitm.timeoutSeconds > NetEvent.noTimeout

				#if os(Linux)
					var filter = Filter.none
					if (evt.events & EPOLLERR.rawValue) != 0 {
						var errData = Int32(0)
						var errLen = socklen_t(MemoryLayout<Int32>.size)
						getsockopt(sock, SOL_SOCKET, SO_ERROR, &errData, &errLen)
						filter = .error(errData)
					} else if (evt.events & EPOLLIN.rawValue) != 0 {
						if qitmIsTimeout {
							// this is a timeout
							filter = .timer
						} else {
							filter = .read
						}
					} else if (evt.events & EPOLLOUT.rawValue) != 0 {
						filter = .write
					}
					if NetEvent.debug {
						print("event rcv \(sock) \(filter) \(evt.events)")
					}
				#else
					var filter = Filter.none
					if evt.filter == Int16(EVFILT_TIMER) {
						filter = .timer
					} else if evt.filter == Int16(EV_ERROR) {
						filter = .error(Int32(evt.data))
					} else if evt.filter == Int16(EVFILT_READ) {
						filter = .read
					} else if evt.filter == Int16(EVFILT_WRITE) {
						filter = .write
					}
					if NetEvent.debug {
						print("event rcv \(sock) \(filter) \(evt.data)")
					}
				#endif

				#if os(Linux)
					epoll_ctl(kq, EPOLL_CTL_DEL, sock, nil)
					if qitm.associated != invalidSocket {
						epoll_ctl(kq, EPOLL_CTL_DEL, qitm.associated, nil)
						queuedSockets.removeValue(forKey: qitm.associated)
						if qitmIsTimeout {
							close(sock)
						} else {
							close(qitm.associated)
						}
					}
					qitm.callback(qitmIsTimeout ? qitm.associated : sock, filter)
				#else
					if qitmIsTimeout {
						// need to either remove the timer or the failed event
						// this could be optimised to do all removes at once
						var tmout = timespec(tv_sec: 0, tv_nsec: 0)
						if case .timer = filter {
							if NetEvent.debug {
								print("event del \(sock) \(qitm.what)")
							}
							var kvt = event(ident: UInt(sock), filter: qitm.what.kqueueFilter, flags: UInt16(EV_DELETE), fflags: 0, data: 0, udata: nil)
							kevent(kq, &kvt, 1, nil, 0, &tmout)
						} else {
							if NetEvent.debug {
								print("event del \(sock) EVFILT_TIMER")
							}
							var kvt = event(ident: UInt(sock), filter: Int16(EVFILT_TIMER), flags: UInt16(EV_DELETE), fflags: 0, data: 0, udata: nil)
							kevent(kq, &kvt, 1, nil, 0, &tmout)
						}
					}
					qitm.callback(sock, filter)
				#endif
				}
			}
		}
	}

	// socket can only be queued with one callback at a time
	public static func add(socket newSocket: SocketType, what: Filter, timeoutSeconds: Double, callback: @escaping EventCallback) {
		NetEvent.initialize()
		let threadingCallback: EventCallback = { s, f in
			netHandleQueue.async {
				callback(s, f)
			}
		}
		guard let n = NetEvent.staticEvent else {
			return
		}
		do {
			_ = n.lock.lock()
			defer {
				_ = n.lock.unlock()
			}
		#if os(Linux)
			var associated = invalidSocket
			if timeoutSeconds > NetEvent.noTimeout {
				associated = timerfd_create(CLOCK_MONOTONIC, Int32(TFD_NONBLOCK))
				var timerspec = itimerspec()
				let waitMillis = Int(timeoutSeconds * 1000.0)
				timerspec.it_value.tv_sec = waitMillis / 1000
				timerspec.it_value.tv_nsec = (waitMillis - (timerspec.it_value.tv_sec * 1000)) * 1000000
				timerspec.it_interval.tv_sec = 0
				timerspec.it_interval.tv_nsec = 0
				timerfd_settime(associated, 0, &timerspec, nil)
				var evt = event()
				evt.events = Filter.read.epollEvent | EPOLLONESHOT.rawValue | EPOLLET.rawValue
				evt.data.fd = associated
				n.queuedSockets[associated] = QueuedSocket(socket: associated, what: .read, timeoutSeconds: timeoutSeconds, callback: threadingCallback, associated: newSocket)
				epoll_ctl(n.kq, EPOLL_CTL_ADD, associated, &evt)
				if NetEvent.debug {
					print("event add \(associated) TIMER for \(newSocket)")
				}
			}
			var evt = event()
			evt.events = what.epollEvent | EPOLLONESHOT.rawValue | EPOLLET.rawValue
			evt.data.fd = newSocket
			n.queuedSockets[newSocket] = QueuedSocket(socket: newSocket, what: what, timeoutSeconds: NetEvent.noTimeout, callback: threadingCallback, associated: associated)
			epoll_ctl(n.kq, EPOLL_CTL_ADD, newSocket, &evt)
			if NetEvent.debug {
				print("event add \(newSocket) \(what) \(what.epollEvent)")
			}
		#else
			n.queuedSockets[newSocket] = QueuedSocket(socket: newSocket, what: what, timeoutSeconds: timeoutSeconds, callback: threadingCallback, associated: invalidSocket)
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
				print("event add \(newSocket) \(what) \(what.kqueueFilter)")
			}
		#endif
		}
	}

	public static func remove(socket oldSocket: SocketType) {
		guard let n = NetEvent.staticEvent else {
			return
		}
		_ = n.lock.lock()
		defer {
			_ = n.lock.unlock()
		}
		do {
			if let old = n.queuedSockets[oldSocket] {
			#if os(Linux)
				if old.associated != invalidSocket {
					epoll_ctl(n.kq, EPOLL_CTL_DEL, old.associated, nil)
					close(old.associated)
					n.queuedSockets.removeValue(forKey: old.associated)
				}
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
