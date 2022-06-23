//
//  HTTP11Response.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2016-06-21.
//	Copyright (C) 2016 PerfectlySoft, Inc.
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

#if os(Linux)
    import SwiftGlibc
#else
    import Darwin
#endif

import PerfectNet
import PerfectThread
import PerfectHTTP

// swiftlint:disable syntactic_sugar
class HTTP11Response: HTTPResponse {
    var status = HTTPResponseStatus.ok
    var headerStore = Array<(HTTPResponseHeader.Name, String)>()
    var bodyBytes = [UInt8]()
    var bodyPrefix = [UInt8]()
    var headers: AnyIterator<(HTTPResponseHeader.Name, String)> {
        var g = headerStore.makeIterator()
        return AnyIterator<(HTTPResponseHeader.Name, String)> {
            g.next()
        }
    }

    var connection: NetTCP {
        return request.connection
    }

    var isStreaming = false
    var wroteHeaders = false
	var contentLengthSet = false
    var completedCallback: (() -> ())?
    let request: HTTPRequest
	var handlers: IndexingIterator<[RequestHandler]>?

    lazy var isKeepAlive: Bool = {
        // http 1.1 is keep-alive unless otherwise noted
        // http 1.0 is keep-alive if specifically noted
        // check header first
        if let connection = request.header(.connection) {
            if connection.lowercased() == "keep-alive" {
                return true
            }
            return false
        }
        return isHTTP11
    }()

    var isHTTP11: Bool {
        let version = request.protocolVersion
        return version.0 == 1 && version.1 == 1
    }

	let filters: IndexingIterator<[[HTTPResponseFilter]]>?

	init(request: HTTPRequest, filters: IndexingIterator<[[HTTPResponseFilter]]>? = nil) {
        self.request = request
		self.filters = filters
        let net = request.connection
        completedCallback = {
            net.close()
        }
    }

    func completed() {
        if let cb = completedCallback {
            cb()
        }
    }

	func next() {
		if let n = handlers?.next() {
			n(request, self)
		} else {
			completed()
		}
	}

	func abort() {
		completedCallback = nil
		connection.close()
	}

    func header(_ named: HTTPResponseHeader.Name) -> String? {
        for (n, v) in headerStore where n == named {
            return v
        }
        return nil
    }

	@discardableResult
    func addHeader(_ name: HTTPResponseHeader.Name, value: String) -> Self {
        headerStore.append((name, value))
		if case .contentLength = name {
			contentLengthSet = true
		}
		return self
    }

	@discardableResult
    func setHeader(_ name: HTTPResponseHeader.Name, value: String) -> Self {
        var fi = [Int]()
        for i in 0..<headerStore.count {
            let (n, _) = headerStore[i]
            if n == name {
                fi.append(i)
            }
        }
        fi = fi.reversed()
        for i in fi {
            headerStore.remove(at: i)
        }
        return addHeader(name, value: value)
    }

    func flush(callback: @escaping (Bool) -> ()) {
		if nil != filters {
			// !FIX! this needs an API change for response filters to let them know 
			// when a call is the last
			request.scratchPad["_flushing_"] = true
		}
        push { ok in
            guard ok else {
                return callback(false)
            }
            if self.isStreaming {
				self.pushNonStreamed(bytes: Array("0\r\n\r\n".utf8), callback: callback)
            } else {
                callback(true)
            }
        }
    }

    func pushHeaders(callback: @escaping (Bool) -> ()) {
        wroteHeaders = true
        if isKeepAlive {
            addHeader(.connection, value: "keep-alive")
		}
        if isStreaming {
            addHeader(.transferEncoding, value: "chunked")
        } else if !contentLengthSet {
            addHeader(.contentLength, value: "\(bodyBytes.count)")
        }
		if let filters = self.filters {
			return filterHeaders(allFilters: filters, callback: callback)
		}
		finishPushHeaders(callback: callback)
    }

	func filterHeaders(allFilters: IndexingIterator<[[HTTPResponseFilter]]>, callback: @escaping (Bool) -> ()) {
		var allFilters = allFilters
		if let prioFilters = allFilters.next() {
			return filterHeaders(allFilters: allFilters, prioFilters: prioFilters.makeIterator(), callback: callback)
		}
		finishPushHeaders(callback: callback)
	}

	func filterHeaders(allFilters: IndexingIterator<[[HTTPResponseFilter]]>,
	                   prioFilters: IndexingIterator<[HTTPResponseFilter]>,
	                   callback: @escaping (Bool) -> ()) {
		var prioFilters = prioFilters
		guard let filter = prioFilters.next() else {
			return filterHeaders(allFilters: allFilters, callback: callback)
		}
		filter.filterHeaders(response: self) { result in
			switch result {
			case .continue:
				self.filterHeaders(allFilters: allFilters, prioFilters: prioFilters, callback: callback)
			case .done:
				self.finishPushHeaders(callback: callback)
			case .halt:
				self.abort()
			}
		}
	}

	func finishPushHeaders(callback: @escaping (Bool) -> ()) {
		let eol = [13, 10] as [UInt8]
		if case .ok = status, request.protocolVersion.1 == 1 {
			bodyPrefix = [72, 84, 84, 80, 47, 49, 46, 49, 32, 50, 48, 48, 32, 79, 75, 13, 10]
		} else {
			bodyPrefix = Array("HTTP/\(request.protocolVersion.0).\(request.protocolVersion.1) \(status)\r\n".utf8)
		}
		for (n, v) in headers {
			bodyPrefix.append(contentsOf: Array((n.standardName + ": " + v).utf8))
			bodyPrefix.append(contentsOf: eol)
		}
		bodyPrefix.append(contentsOf: eol)
		push(callback: callback)
	}

	func filterBodyBytes(allFilters: IndexingIterator<[[HTTPResponseFilter]]>, callback: ([UInt8]) -> ()) {
		var allFilters = allFilters
		if let prioFilters = allFilters.next() {
			return filterBodyBytes(allFilters: allFilters, prioFilters: prioFilters.makeIterator(), callback: callback)
		}
		finishFilterBodyBytes(callback: callback)
	}

	func filterBodyBytes(allFilters: IndexingIterator<[[HTTPResponseFilter]]>,
	                     prioFilters: IndexingIterator<[HTTPResponseFilter]>,
	                     callback: ([UInt8]) -> ()) {
		var prioFilters = prioFilters
		guard let filter = prioFilters.next() else {
			return filterBodyBytes(allFilters: allFilters, callback: callback)
		}
		filter.filterBody(response: self) { result in
			switch result {
			case .continue:
				self.filterBodyBytes(allFilters: allFilters, prioFilters: prioFilters, callback: callback)
			case .done:
				self.finishFilterBodyBytes(callback: callback)
			case .halt:
				self.abort()
			}
		}
	}

	func finishFilterBodyBytes(callback: (_ bodyBytes: [UInt8]) -> ()) {
		let bytes = bodyBytes
		bodyBytes = []
		callback(bytes)
	}

	func filteredBodyBytes(callback: (_ bodyBytes: [UInt8]) -> ()) {
		if let filters = self.filters {
			return filterBodyBytes(allFilters: filters, callback: callback)
		}
		finishFilterBodyBytes(callback: callback)
	}

    func push(callback: @escaping (Bool) -> ()) {
        if !wroteHeaders {
            return pushHeaders(callback: callback)
		}
		filteredBodyBytes { bytes in
			if self.isStreaming {
				return self.pushStreamed(bytes: bytes, callback: callback)
			}
			self.pushNonStreamed(bytes: bytes, callback: callback)
		}
    }

    func pushStreamed(bytes: [UInt8], callback: @escaping (Bool) -> ()) {
		let bodyCount = bytes.count
		guard bodyCount > 0 else {
			return callback(true)
		}
		let hexString = "\(String(bodyCount, radix: 16, uppercase: true))\r\n"
		let sendA = Array(hexString.utf8)
		pushNonStreamed(bytes: sendA) { ok in
			guard ok else {
				return self.abort()
			}
			self.pushNonStreamed(bytes: bytes) { ok in
				guard ok else {
					return self.abort()
				}
				self.pushNonStreamed(bytes: Array("\r\n".utf8), callback: callback)
			}
		}
    }

    func pushNonStreamed(bytes: [UInt8], callback: @escaping (Bool) -> ()) {
		if !bodyPrefix.isEmpty {
			let newBytes = bodyPrefix + bytes
			bodyPrefix = []
			return pushNonStreamed(bytes: newBytes, callback: callback)
		}
        let bodyCount = bytes.count
        guard bodyCount > 0 else {
            return callback(true)
        }
        connection.write(bytes: bytes) { sent in
            guard bodyCount == sent else {
                return self.abort()
            }
            netHandleQueue.async {
                callback(true)
            }
        }
    }
}
