//
//  HTTP2SessionSettings.swift
//  PerfectHTTPServer
//
//  Created by Kyle Jessup on 2017-06-20.
//
//

typealias HTTP2Setting = UInt16

let headerTableSize: HTTP2Setting = 0x1
let enablePush: HTTP2Setting = 0x2
let maxConcurrentStreams: HTTP2Setting = 0x3
let initialWindowSize: HTTP2Setting = 0x4
let maxFrameSize: HTTP2Setting = 0x5
let maxHeaderListSize: HTTP2Setting = 0x6

struct HTTP2SessionSettings {
	var headerTableSize: Int
	var enablePush: Bool
	var maxConcurrentStreams: Int
	var initialWindowSize: Int
	var maxFrameSize: Int
	var maxHeaderListSize: Int

	init() {
		headerTableSize = 4096
		enablePush = true
		maxConcurrentStreams = Int.max
		initialWindowSize = 65535
		maxFrameSize = 16384
		maxHeaderListSize = Int.max
	}
}
