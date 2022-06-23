//
//  HTTP2Session.swift
//  PerfectHTTPServer
//
//  Created by Kyle Jessup on 2017-06-20.
//
//

import PerfectNet
import PerfectLib
import PerfectThread
import PerfectHTTP

// !FIX! need a better scheme for this
let receiveWindowLowWater = 10_240
let receiveWindowTopOff: Int = 25_169_664 // 1024*1*1024

// receives notification of an unexpected network shutdown
protocol HTTP2NetErrorDelegate: AnyObject {
	func networkShutdown()
}

protocol HTTP2FrameReceiver: AnyObject {
	func receiveFrame(_ frame: HTTP2Frame)
}

struct HTTP2FlowWindows {
	var serverWindowSize: Int
	var clientWindowSize: Int
}

extension Bytes {
	@discardableResult
	func importFrame32(_ int: UInt32) -> Self {
		import32Bits(from: int.hostToNet)
		return self
	}

	@discardableResult
	func importFrame32(_ int: Int) -> Self {
		import32Bits(from: UInt32(int).hostToNet)
		return self
	}

	@discardableResult
	func importFrame16(_ int: UInt16) -> Self {
		import16Bits(from: int.hostToNet)
		return self
	}
}

// A single HTTP/2 connection handling multiple requests and responses
class HTTP2Session: Hashable, HTTP2NetErrorDelegate, HTTP2FrameReceiver {

	enum SessionState {
		case setup
		case active
	}

	private static let pinLock = Threading.Lock()
	private static var pins = Set<HTTP2Session>()

	static func == (lhs: HTTP2Session, rhs: HTTP2Session) -> Bool {
		return lhs.net.fd.fd == rhs.net.fd.fd
	}

    func hash(into hasher: inout Hasher) {
        hasher.combine(Int(net.fd.fd))
    }

	let net: NetTCP
	let server: HTTPServer
	var debug = false

	var frameReader: HTTP2FrameReader?
	var frameWriter: HTTP2FrameWriter?

	var clientSettings = HTTP2SessionSettings()
	var serverSettings = HTTP2SessionSettings()
	var connectionFlowWindows: HTTP2FlowWindows
	var state = SessionState.setup

	let decoder = HPACKDecoder()
	let encoder = HPACKEncoder()
	let encoderLock = Threading.Lock()

	fileprivate let streamsLock = Threading.Lock()
	fileprivate var streams = [UInt32: HTTP2Request]()

	init(_ net: NetTCP,
	     server: HTTPServer,
	     debug: Bool = http2Debug) {
		self.net = net
		self.server = server
		self.debug = debug
		self.connectionFlowWindows = HTTP2FlowWindows(serverWindowSize: 65535, clientWindowSize: 65535)
		frameReader = HTTP2FrameReader(net, frameReceiver: self, errorDelegate: self)
		frameWriter = HTTP2FrameWriter(net, errorDelegate: self)
		pinSelf()
		sendInitialSettings()
	}

	deinit {
		if debug {
			print("~HTTP2Session")
		}
	}

	private func pinSelf() {
		HTTP2Session.pinLock.lock()
		HTTP2Session.pins.insert(self)
		HTTP2Session.pinLock.unlock()
	}

	private func unpinSelf() {
		HTTP2Session.pinLock.lock()
		HTTP2Session.pins.remove(self)
		HTTP2Session.pinLock.unlock()
	}

	func sendInitialSettings() {
		// !FIX! need to make this configurable

		serverSettings.headerTableSize = 4096
		serverSettings.maxConcurrentStreams = 100
		serverSettings.initialWindowSize = 65535

		let b = Bytes()
		b.importFrame16(headerTableSize)
			.importFrame32(UInt32(serverSettings.headerTableSize))
		b.importFrame16(maxConcurrentStreams)
			.importFrame32(UInt32(serverSettings.maxConcurrentStreams))
		b.importFrame16(initialWindowSize)
			.importFrame32(UInt32(serverSettings.initialWindowSize))
		do {
			let frame = HTTP2Frame(type: .settings, payload: b.data)
			frameWriter?.enqueueFrame(frame)
			if debug {
                // swiftlint:disable line_length
				print("server settings:\n\theaderTableSize: \(serverSettings.headerTableSize)\n\tenablePush: \(serverSettings.enablePush)\n\tmaxConcurrentStreams: \(serverSettings.maxConcurrentStreams)\n\tinitialWindowSize: \(serverSettings.initialWindowSize)\n\tmaxFrameSize: \(serverSettings.maxFrameSize)\n\tmaxHeaderListSize: \(serverSettings.maxHeaderListSize)")
			}
		}
	}

	func networkShutdown() {
		net.shutdown()
		unpinSelf()
	}

	func fatalError(streamId: UInt32 = 0, error: HTTP2Error, msg: String) {
		if streamId != 0 {
			removeRequest(streamId)
		}
		let bytes = Bytes()
		bytes.importFrame32(UInt32(streamId))
			.importFrame32(error.rawValue)
			.importBytes(from: Array(msg.utf8))
		let frame = HTTP2Frame(type: .goAway, payload: bytes.data)
		frameWriter?.enqueueFrame(frame)
		frameWriter?.waitUntilEmpty {
			self.networkShutdown()
		}
	}
}

extension HTTP2Session {
	func getRequest(_ streamId: UInt32) -> HTTP2Request? {
		streamsLock.lock()
		defer {
			streamsLock.unlock()
		}
		return streams[streamId]
	}

	func putRequest(_ request: HTTP2Request) -> Bool {
		streamsLock.lock()
		defer {
			streamsLock.unlock()
		}
		if streams.count >= serverSettings.maxConcurrentStreams {
			return false
		}
		streams[request.streamId] = request
		return true
	}

	func removeRequest(_ streamId: UInt32) {
		streamsLock.lock()
		defer {
			streamsLock.unlock()
		}
		streams.removeValue(forKey: streamId)
	}
}

extension HTTP2Session {
	// this is called on the main frame reading thread
	func receiveFrame(_ frame: HTTP2Frame) {
		if debug {
			print("recv frame: \(frame.type)")
		}
		if state == .setup && frame.type != .settings {
			fatalError(error: .protocolError, msg: "Settings expected")
			return
		}
		if frame.streamId == 0 {
			switch frame.type {
			case .settings:
				settingsFrame(frame)
			case .ping:
				pingFrame(frame)
			case .goAway:
				goAwayFrame(frame)
			case .windowUpdate:
				windowUpdateFrame(frame)
			default:
				fatalError(error: .protocolError, msg: "Frame requires stream id")
			}
		} else {
			switch frame.type {
			case .headers:
				headersFrame(frame)
			case .continuation:
				continuationFrame(frame)
			case .data:
				dataFrame(frame)
			case .priority:
				priorityFrame(frame)
			case .cancelStream:
				cancelStreamFrame(frame)
			case .windowUpdate:
				windowUpdateFrame(frame)
			default:
				fatalError(error: .protocolError, msg: "Invalid frame with stream id")
			}
		}
	}

	func settingsFrame(_ frame: HTTP2Frame) {
		let isAck = (frame.flags & flagSettingsAck) != 0
		if !isAck { // ACK settings receipt
			state = .active
			if let payload = frame.payload {
				processSettingsPayload(Bytes(existingBytes: payload))
			}
			let response = HTTP2Frame(type: HTTP2FrameType.settings,
			                          flags: flagSettingsAck)
			frameWriter?.enqueueFrame(response)
		} else {
			if debug {
				print("\tack")
			}
			increaseServerConnectionWindow(by: receiveWindowTopOff)
		}
	}

	func windowUpdateFrame(_ frame: HTTP2Frame) {
		guard let b = frame.payload, b.count == 4 else {
			return fatalError(error: .protocolError, msg: "Invalid frame")
		}
		let bytes = Bytes(existingBytes: b)
		let windowSize = Int(bytes.export32Bits().netToHost)
		guard windowSize > 0 else {
			return fatalError(error: .protocolError, msg: "Received window size of zero")
		}
		if frame.streamId == 0 {
			increaseClientConnectionWindow(by: windowSize)
		} else {
			increaseClientWindow(stream: frame.streamId, by: windowSize)
		}
	}

	func headersFrame(_ frame: HTTP2Frame) {
		let streamId = frame.streamId
		let request = HTTP2Request(streamId, session: self)
		if putRequest(request) {
			request.headersFrame(frame)
		} else {
			let frame = HTTP2Frame(type: .cancelStream, streamId: frame.streamId, payload: Bytes().importFrame32(HTTP2Error.refusedStream.rawValue).data)
			frameWriter?.enqueueFrame(frame)
		}
	}

	func continuationFrame(_ frame: HTTP2Frame) {
		let streamId = frame.streamId
		guard let request = getRequest(streamId) else {
			return fatalError(error: .streamClosed, msg: "Invalid stream id")
		}
		request.continuationFrame(frame)
	}

	func dataFrame(_ frame: HTTP2Frame) {
		let streamId = frame.streamId
		guard let request = getRequest(streamId) else {
			return fatalError(error: .streamClosed, msg: "Invalid stream id")
		}
		let count = frame.payload?.count ?? 0
		if connectionFlowWindows.serverWindowSize - count < receiveWindowLowWater {
			increaseServerConnectionWindow(by: receiveWindowTopOff)
		}
		if request.streamFlowWindows.serverWindowSize - count < receiveWindowLowWater {
			increaseServerWindow(stream: request.streamId, by: receiveWindowTopOff)
		}
		connectionFlowWindows.serverWindowSize -= count
		request.streamFlowWindows.serverWindowSize -= count
		request.dataFrame(frame)
	}

	func priorityFrame(_ frame: HTTP2Frame) {
		let streamId = frame.streamId
		guard let request = getRequest(streamId) else {
			// Firefox will send this before HEADERS, with the new stream id
			return // fatalError(error: .streamClosed, msg: "Invalid stream id")
		}
		request.priorityFrame(frame)
	}

	func cancelStreamFrame(_ frame: HTTP2Frame) {
		let streamId = frame.streamId
		guard let request = getRequest(streamId) else {
			return // fatalError(error: .streamClosed, msg: "Invalid stream id")
		}
		request.cancelStreamFrame(frame)
		if debug {
			print("\t\(streamId)")
		}
	}

	func pingFrame(_ frame: HTTP2Frame) {
		guard frame.streamId == 0 else {
			fatalError(error: .protocolError, msg: "Ping contained stream id")
			return
		}
		let frame = HTTP2Frame(type: .ping, flags: flagPingAck, streamId: 0, payload: frame.payload)
		frameWriter?.enqueueFrame(frame, highPriority: true)
	}

	func goAwayFrame(_ frame: HTTP2Frame) {
		if let bytes = frame.payload {
			let b = Bytes(existingBytes: bytes)
			let lastStreamId = b.export32Bits().netToHost
			let errorCode = b.export32Bits().netToHost
			let remainingBytes = b.exportBytes(count: b.availableExportBytes)
			let errorStr = String(validatingUTF8: remainingBytes)
			if debug {
				print("Bye: last stream: \(lastStreamId) \(HTTP2Error(rawValue: errorCode)?.rawValue ?? 0) \(errorStr ?? "")")
			}
		}
		networkShutdown()
	}
}

extension HTTP2Session {
	// send a WINDOW_UPDATE stream 0
	func increaseServerConnectionWindow(by: Int) {
		let frame = HTTP2Frame(type: .windowUpdate, payload: Bytes().importFrame32(receiveWindowTopOff).data)
		frameWriter?.enqueueFrame(frame)
		connectionFlowWindows.serverWindowSize += by
		if debug {
			print("send frame: windowUpdate \t+\(by) for connection = \(connectionFlowWindows.serverWindowSize)")
		}
	}

	// received a WINDOW_UPDATE stream 0
	func increaseClientConnectionWindow(by: Int) {
		connectionFlowWindows.clientWindowSize += by
		if debug {
			print("\t+\(by) for connection = \(connectionFlowWindows.clientWindowSize)")
		}
		// unblock any stalled requests
		streamsLock.lock()
		defer {
			streamsLock.unlock()
		}
		streams.forEach { tup in
			if let u = tup.value.unblockCallback {
				tup.value.unblockCallback = nil
				u()
			}
		}
	}

	// received a WINDOW_UPDATE for stream x
	func increaseClientWindow(stream: UInt32, by: Int) {
		guard let request = getRequest(stream) else {
			return
		}
		request.streamFlowWindows.clientWindowSize += by
		if let u = request.unblockCallback {
			request.unblockCallback = nil
			u()
		}
		if debug {
			print("\t+\(by) for stream \(stream) = \(request.streamFlowWindows.clientWindowSize)")
		}
	}

	// send a WINDOW_UPDATE for stream x
	func increaseServerWindow(stream: UInt32, by: Int) {
		guard let request = getRequest(stream) else {
			return
		}
		let frame = HTTP2Frame(type: .windowUpdate, streamId: stream, payload: Bytes().importFrame32(receiveWindowTopOff).data)
		frameWriter?.enqueueFrame(frame)
		request.streamFlowWindows.serverWindowSize += by
		if debug {
			print("send frame: windowUpdate \t+\(by) for stream \(stream) = \(request.streamFlowWindows.serverWindowSize)")
		}
	}

	// send a WINDOW_UPDATE for stream x
	func decreaseClientWindow(stream: UInt32, by: Int) {
		guard let request = getRequest(stream) else {
			return
		}
		request.streamFlowWindows.clientWindowSize -= by
		connectionFlowWindows.clientWindowSize -= by
	}
}

extension HTTP2Session {
	func processSettingsPayload(_ b: Bytes) {
		while b.availableExportBytes >= 6 {
			let identifier = b.export16Bits().netToHost
			let value = Int(b.export32Bits().netToHost)
			switch identifier {
			case settingsHeaderTableSize:
				clientSettings.headerTableSize = Int(value)
				decoder.setMaxHeaderTableSize(maxHeaderTableSize: Int(value))
			case settingsEnablePush:
				clientSettings.enablePush = value == 1
			case settingsMaxConcurrentStreams:
				clientSettings.maxConcurrentStreams = value
			case settingsInitialWindowSize:
				clientSettings.initialWindowSize = value
				// !FIX! need to update all active streams by the difference between new and old values
			case settingsMaxFrameSize:
				guard value <= 16777215 else {
					fatalError(error: .protocolError, msg: "Max frame size too large")
					return
				}
				clientSettings.maxFrameSize = value
			case settingsMaxHeaderListSize:
				clientSettings.maxHeaderListSize = value
			default:
				() // must ignore unrecognized settings
			}
		}
		if debug {
			print("client settings:")
			print("\theaderTableSize: \(clientSettings.headerTableSize)")
			print("\tenablePush: \(clientSettings.enablePush)")
			print("\tmaxConcurrentStreams: \(clientSettings.maxConcurrentStreams)")
			print("\tinitialWindowSize: \(clientSettings.initialWindowSize)")
			print("\tmaxFrameSize: \(clientSettings.maxFrameSize)")
			print("\tmaxHeaderListSize: \(clientSettings.maxHeaderListSize)")
		}
	}
}
