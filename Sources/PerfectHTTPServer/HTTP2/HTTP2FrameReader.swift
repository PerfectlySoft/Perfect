//
//  HTTP2FrameReader.swift
//  PerfectHTTPServer
//
//  Created by Kyle Jessup on 2017-06-20.
//
//

import PerfectNet
import PerfectThread
import Dispatch

enum HTTP2FrameSubscriptionType: UInt8 {
	case headers = 0x1
	case settings = 0x4
	case pushPromise = 0x5
	case ping = 0x6
	case goAway = 0x7
	case windowUpdate = 0x8
	case sessionTimeout = 0xFF
}

class HTTP2FrameReader {
	private let net: NetTCP
	private weak var errorDelegate: HTTP2NetErrorDelegate?
	private weak var frameReceiver: HTTP2FrameReceiver?

	private var readFrames = [HTTP2Frame]()
	private let readFramesEvent = Threading.Event()

	// no frames in queue and no frames read
	var noFrameReadTimeout = 60.0*5.0
	private let readFramesThread = DispatchQueue(label: "HTTP2FrameReader")

	private let processFramesThread = DispatchQueue(label: "HTTP2FrameProcessor")

	private var shouldTimeout: Bool {
		readFramesEvent.lock()
		defer {
			readFramesEvent.unlock()
		}
		return readFrames.isEmpty
	}

	init(_ net: NetTCP, frameReceiver: HTTP2FrameReceiver, errorDelegate: HTTP2NetErrorDelegate) {
		self.net = net
		self.frameReceiver = frameReceiver
		self.errorDelegate = errorDelegate
		startReadFrames()
	}

	private func startReadFrames() {
		readFramesThread.async {
			self.readHTTP2Frame { frame in
				if let frame = frame, let frameReceiver = self.frameReceiver {
					frameReceiver.receiveFrame(frame)
					self.startReadFrames() // evaluate if this should just be a loop
				} // else we are dead. stop reading
			}
		}
	}

	private func readHTTP2Frame(callback: @escaping (HTTP2Frame?) -> ()) {
		let net = self.net
		net.readBytesFully(count: 9, timeoutSeconds: noFrameReadTimeout) { bytes in
			if let b = bytes {
				var header = self.bytesToHeader(b)
				let length = Int(header.length)
				if length > 0 {
					net.readBytesFully(count: length, timeoutSeconds: self.noFrameReadTimeout) { bytes in
						guard let bytes = bytes, bytes.count == length else {
							callback(nil)
							self.errorDelegate?.networkShutdown()
							return
						}
						header.payload = bytes
						callback(header)
					}
				} else {
					callback(header)
				}
			} else {
				callback(nil)
				self.errorDelegate?.networkShutdown()
			}
		}
	}

	private func bytesToHeader(_ b: [UInt8]) -> HTTP2Frame {
		let payloadLength = (UInt32(b[0]) << 16) + (UInt32(b[1]) << 8) + UInt32(b[2])
		let type = b[3]
		let flags = b[4]
		var sid = UInt32(b[5])
		sid <<= 8
		sid += UInt32(b[6])
		sid <<= 8
		sid += UInt32(b[7])
		sid <<= 8
		sid += UInt32(b[8])
		sid &= ~0x80000000
		return HTTP2Frame(length: payloadLength, type: type, flags: flags, streamId: sid, payload: nil)
	}
}
