//
//  cURL.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2015-08-10.
//	Copyright (C) 2015 PerfectlySoft, Inc.
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

import cURL

/// This class is a wrapper around the CURL library. It permits network operations to be completed using cURL in a block or non-blocking manner.
public class CURL {
	
	static var sInit:Int = {
		curl_global_init(Int(CURL_GLOBAL_SSL | CURL_GLOBAL_WIN32))
		return 1
	}()
	
	var curl: UnsafeMutablePointer<Void>?
	var multi: UnsafeMutablePointer<Void>?
	
	var slists = [UnsafeMutablePointer<curl_slist>]()
	
	var headerBytes = [UInt8]()
	var bodyBytes = [UInt8]()
	
	/// The CURLINFO_RESPONSE_CODE for the last operation.
	public var responseCode: Int {
		return self.getInfo(CURLINFO_RESPONSE_CODE).0
	}
	
	/// Get or set the current URL.
	public var url: String {
		get {
			return self.getInfo(CURLINFO_EFFECTIVE_URL).0
		}
		set {
			self.setOption(CURLOPT_URL, s: newValue)
		}
	}
	
	/// Initialize the CURL request.
	public init() {
		self.curl = curl_easy_init()
		setCurlOpts()
	}
	
	/// Initialize the CURL request with a given URL.
	public convenience init(url: String) {
		self.init()
		self.url = url
	}
	
	/// Duplicate the given request into a new CURL object.
	public init(dupeCurl: CURL) {
		if let copyFrom = dupeCurl.curl {
			self.curl = curl_easy_duphandle(copyFrom)
		} else {
			self.curl = curl_easy_init()
		}
		setCurlOpts() // still set options
	}
	
	func setCurlOpts() {
		curl_easy_setopt_long(self.curl!, CURLOPT_NOSIGNAL, 1)
	#if swift(>=3.0)
		let opaqueMe = UnsafeMutablePointer<Void>(OpaquePointer(bitPattern: Unmanaged.passUnretained(self)))
	#else
		let opaqueMe = UnsafeMutablePointer<Void>(Unmanaged.passUnretained(self).toOpaque())
	#endif
	#if os(Linux)
		setOption(CURLOPT_WRITEHEADER, v: opaqueMe)
		setOption(CURLOPT_FILE, v: opaqueMe)
		setOption(CURLOPT_INFILE, v: opaqueMe)
	#else
		setOption(CURLOPT_HEADERDATA, v: opaqueMe)
		setOption(CURLOPT_WRITEDATA, v: opaqueMe)
		setOption(CURLOPT_READDATA, v: opaqueMe)
	#endif
		let headerReadFunc: curl_func = {
			(a, size, num, p) -> Int in
		#if swift(>=3.0)
			let crl = Unmanaged<CURL>.fromOpaque(OpaquePointer(p!)).takeUnretainedValue()
			if let bytes = UnsafeMutablePointer<UInt8>(a) {
				let fullCount = size*num
				for idx in 0..<fullCount {
					crl.headerBytes.append(bytes[idx])
				}
				return fullCount
			}
		#else
			let crl = Unmanaged<CURL>.fromOpaque(OpaquePointer(p)).takeUnretainedValue()
			let bytes = UnsafeMutablePointer<UInt8>(a)
			if nil != bytes {
				let fullCount = size*num
				for idx in 0..<fullCount {
					crl.headerBytes.append(bytes[idx])
				}
				return fullCount
			}
		#endif
			return 0
		}
		setOption(CURLOPT_HEADERFUNCTION, f: headerReadFunc)
		
		let writeFunc: curl_func = {
			(a, size, num, p) -> Int in
			
		#if swift(>=3.0)
			let crl = Unmanaged<CURL>.fromOpaque(OpaquePointer(p!)).takeUnretainedValue()
			if let bytes = UnsafeMutablePointer<UInt8>(a) {
				let fullCount = size*num
				for idx in 0..<fullCount {
					crl.bodyBytes.append(bytes[idx])
				}
				return fullCount
			}
		#else
			let crl = Unmanaged<CURL>.fromOpaque(OpaquePointer(p)).takeUnretainedValue()
			let bytes = UnsafeMutablePointer<UInt8>(a)
			if nil != bytes {
				let fullCount = size*num
				for idx in 0..<fullCount {
					crl.bodyBytes.append(bytes[idx])
				}
				return fullCount
			}
		#endif
			return 0
		}
		setOption(CURLOPT_WRITEFUNCTION, f: writeFunc)
		
		let readFunc: curl_func = {
			(a, b, c, p) -> Int in
			
			// !FIX!
			
//			let crl = Unmanaged<CURL>.fromOpaque(COpaquePointer(p)).takeUnretainedValue()
			return 0
		}
		setOption(CURLOPT_READFUNCTION, f: readFunc)
		
	}
	
	/// Clean up and reset the CURL object.
	public func reset() {
		if self.curl != nil {
			if self.multi != nil {
				curl_multi_remove_handle(self.multi!, self.curl!)
				self.multi = nil
			}
			while self.slists.count > 0 {
				curl_slist_free_all(self.slists.last!)
				self.slists.removeLast()
			}
			curl_easy_reset(self.curl!)
			setCurlOpts()
		}
	}
	
	/// Perform the CURL request in a non-blocking manner. The closure will be called with the resulting code, header and body data.
	public func perform(closure: (Int, [UInt8], [UInt8]) -> ()) {
		
		let header = Bytes()
		let body = Bytes()
		
		self.multi = curl_multi_init()
		curl_multi_add_handle(self.multi!, self.curl!)
		
		performInner(header: header, body: body, closure: closure)
	}
	
	private func performInner(header headr: Bytes, body: Bytes, closure: (Int, [UInt8], [UInt8]) -> ()) {
		let perf = self.perform()
		if let h = perf.2 {
			headr.importBytes(from: h)
		} 
		if let b = perf.3 {
			body.importBytes(from: b)
		}
		if perf.0 == false { // done
			closure(perf.1, headr.data, body.data)
		} else {
			Threading.dispatch {
				self.performInner(header: headr, body: body, closure: closure)
			}
		}
	}
	
	/// Performs the request, blocking the current thread until it completes.
	/// - returns: A tuple consisting of: Int - the result code, [UInt8] - the header bytes if any, [UInt8] - the body bytes if any
	public func performFully() -> (Int, [UInt8], [UInt8]) {
		
		let code = curl_easy_perform(self.curl!)
		defer {
			if self.headerBytes.count > 0 {
				self.headerBytes = [UInt8]()
			}
			if self.bodyBytes.count > 0 {
				self.bodyBytes = [UInt8]()
			}
			self.reset()
		}
		if code != CURLE_OK {
			let str = self.strError(code: code)
			print(str)
		}
		return (Int(code.rawValue), self.headerBytes, self.bodyBytes)
	}
	
	/// Performs a bit of work on the current request.
	/// - returns: A tuple consisting of: Bool - should perform() be called again, Int - the result code, [UInt8] - the header bytes if any, [UInt8] - the body bytes if any
	public func perform() -> (Bool, Int, [UInt8]?, [UInt8]?) {
		if self.multi == nil {
			self.multi = curl_multi_init()
			curl_multi_add_handle(self.multi!, self.curl!)
		}
		var one: Int32 = 0
		var code = CURLM_OK
		repeat {
		
			code = curl_multi_perform(self.multi!, &one)
			
		} while code == CURLM_CALL_MULTI_PERFORM
		
		guard code == CURLM_OK else {
			return (false, Int(code.rawValue), nil, nil)
		}
		var two: Int32 = 0
		let msg = curl_multi_info_read(self.multi!, &two)
		
		defer {
			if self.headerBytes.count > 0 {
				self.headerBytes = [UInt8]()
			}
			if self.bodyBytes.count > 0 {
				self.bodyBytes = [UInt8]()
			}
		}
		
		if msg != nil {
			let msgResult = curl_get_msg_result(msg)
			guard msgResult == CURLE_OK else {
				return (false, Int(msgResult.rawValue), nil, nil)
			}
			return (false, Int(msgResult.rawValue),
				self.headerBytes.count > 0 ? self.headerBytes : nil,
				self.bodyBytes.count > 0 ? self.bodyBytes : nil)
		}
		return (true, 0,
			self.headerBytes.count > 0 ? self.headerBytes : nil,
			self.bodyBytes.count > 0 ? self.bodyBytes : nil)
	}
	
//	/// Returns the result code for the last
//	public func multiResult() -> CURLcode {
//		var two: Int32 = 0
//		let msg = curl_multi_info_read(self.multi!, &two)
//		if msg != nil && msg.memory.msg == CURLMSG_DONE {
//			return curl_get_msg_result(msg)
//		}
//		return CURLE_OK
//	}
	
	/// Returns the String message for the given CURL result code.
	public func strError(code cod: CURLcode) -> String {
		return String(validatingUTF8: curl_easy_strerror(cod))!
	}
	
	/// Returns the Int value for the given CURLINFO.
	public func getInfo(_ info: CURLINFO) -> (Int, CURLcode) {
		var i = 0
		let c = curl_easy_getinfo_long(self.curl!, info, &i)
		return (i, c)
	}
	
	/// Returns the String value for the given CURLINFO.
	public func getInfo(_ info: CURLINFO) -> (String, CURLcode) {
	#if swift(>=3.0)
		let i = UnsafeMutablePointer<UnsafePointer<Int8>?>.allocatingCapacity(1)
		defer { i.deinitialize(count: 1); i.deallocateCapacity(1) }
		let code = curl_easy_getinfo_cstr(self.curl!, info, i)
		return (code != CURLE_OK ? "" : String(validatingUTF8: i.pointee!)!, code)
	#else
		let i = UnsafeMutablePointer<UnsafePointer<Int8>>.allocatingCapacity(1)
		defer { i.deinitialize(count: 1); i.deallocateCapacity(1) }
		let code = curl_easy_getinfo_cstr(self.curl!, info, i)
		return (code != CURLE_OK ? "" : String(validatingUTF8: i.pointee)!, code)
	#endif
	}
	
	/// Sets the Int64 option value.
	public func setOption(_ option: CURLoption, int: Int64) -> CURLcode {
		return curl_easy_setopt_int64(self.curl!, option, int)
	}
	
	/// Sets the Int option value.
	public func setOption(_ option: CURLoption, int: Int) -> CURLcode {
		return curl_easy_setopt_long(self.curl!, option, int)
	}
	
	/// Sets the poionter option value.
	public func setOption(_ option: CURLoption, v: UnsafeMutablePointer<Void>) -> CURLcode {
		return curl_easy_setopt_void(self.curl!, option, v)
	}
	
	/// Sets the callback function option value.
	public func setOption(_ option: CURLoption, f: curl_func) -> CURLcode {
		return curl_easy_setopt_func(self.curl!, option, f)
	}
	
	/// Sets the String option value.
	public func setOption(_ option: CURLoption, s: String) -> CURLcode {
		switch(option.rawValue) {
		case CURLOPT_HTTP200ALIASES.rawValue,
			CURLOPT_HTTPHEADER.rawValue,
			CURLOPT_POSTQUOTE.rawValue,
			CURLOPT_PREQUOTE.rawValue,
			CURLOPT_QUOTE.rawValue,
			CURLOPT_MAIL_FROM.rawValue,
			CURLOPT_MAIL_RCPT.rawValue:
		#if swift(>=3.0)
			guard let slist = curl_slist_append(nil, s) else {
				return CURLE_OUT_OF_MEMORY
			}
		#else
			let slist = curl_slist_append(nil, s)
			guard nil != slist else {
				return CURLE_OUT_OF_MEMORY
			}
		#endif
			self.slists.append(slist)
			return curl_easy_setopt_slist(self.curl!, option, slist)
		default:
			()
		}
		return curl_easy_setopt_cstr(self.curl!, option, s)
	}
	
	/// Cleanup and close the CURL request.
	public func close() {
		if self.curl != nil {
			if self.multi != nil {
				curl_multi_cleanup(self.multi!)
				self.multi = nil
			}
			curl_easy_cleanup(self.curl!)
			
			self.curl = nil
			while self.slists.count > 0 {
				curl_slist_free_all(self.slists.last!)
				self.slists.removeLast()
			}
		}
	}
	
	deinit {
		self.close()
	}
}

