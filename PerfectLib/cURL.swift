//
//  cURL.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2015-08-10.
//	Copyright (C) 2015 PerfectlySoft, Inc.
//
//	This program is free software: you can redistribute it and/or modify
//	it under the terms of the GNU Affero General Public License as
//	published by the Free Software Foundation, either version 3 of the
//	License, or (at your option) any later version, as supplemented by the
//	Perfect Additional Terms.
//
//	This program is distributed in the hope that it will be useful,
//	but WITHOUT ANY WARRANTY; without even the implied warranty of
//	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//	GNU Affero General Public License, as supplemented by the
//	Perfect Additional Terms, for more details.
//
//	You should have received a copy of the GNU Affero General Public License
//	and the Perfect Additional Terms that immediately follow the terms and
//	conditions of the GNU Affero General Public License along with this
//	program. If not, see <http://www.perfect.org/AGPL_3_0_With_Perfect_Additional_Terms.txt>.
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
		return getInfo(CURLINFO_RESPONSE_CODE).0
	}
	
	/// Get or set the current URL.
	public var url: String {
		get {
			return getInfo(CURLINFO_EFFECTIVE_URL).0
		}
		set {
			setOption(CURLOPT_URL, s: newValue)
		}
	}
	
	/// Initialize the CURL request.
	public init() {
		curl = curl_easy_init()
		setCurlOpts()
	}
	
	/// Initialize the CURL request with a given URL.
	public convenience init(withURL: String) {
		self.init()
		url = withURL
	}
	
	/// Duplicate the given request into a new CURL object.
	public init(dupeCurl: CURL) {
		if let copyFrom = dupeCurl.curl {
			curl = curl_easy_duphandle(copyFrom)
		} else {
			curl = curl_easy_init()
		}
		setCurlOpts() // still set options
	}
	
	func setCurlOpts() {
		curl_easy_setopt_long(curl!, CURLOPT_NOSIGNAL, 1)
		let opaqueMe = UnsafeMutablePointer<Void>(Unmanaged.passUnretained(self).toOpaque())
		setOption(CURLOPT_HEADERDATA, v: opaqueMe)
		setOption(CURLOPT_WRITEDATA, v: opaqueMe)
		setOption(CURLOPT_READDATA, v: opaqueMe)
		
		let headerReadFunc: curl_func = {
			(a: UnsafeMutablePointer<Void>, size: Int, num: Int, p: UnsafeMutablePointer<Void>) -> Int in
			
			let crl = Unmanaged<CURL>.fromOpaque(COpaquePointer(p)).takeUnretainedValue()
			let bytes = UnsafeMutablePointer<UInt8>(a)
			let fullCount = size*num
			for idx in 0..<fullCount {
				crl.headerBytes.append(bytes[idx])
			}
			return fullCount
		}
		setOption(CURLOPT_HEADERFUNCTION, f: headerReadFunc)
		
		let writeFunc: curl_func = {
			(a: UnsafeMutablePointer<Void>, size: Int, num: Int, p: UnsafeMutablePointer<Void>) -> Int in
			
			let crl = Unmanaged<CURL>.fromOpaque(COpaquePointer(p)).takeUnretainedValue()
			let bytes = UnsafeMutablePointer<UInt8>(a)
			let fullCount = size*num
			for idx in 0..<fullCount {
				crl.bodyBytes.append(bytes[idx])
			}
			return fullCount
		}
		setOption(CURLOPT_WRITEFUNCTION, f: writeFunc)
		
		let readFunc: curl_func = {
			(a: UnsafeMutablePointer<Void>, b: Int, c: Int, p: UnsafeMutablePointer<Void>) -> Int in
			
			// !FIX!
			
//			let crl = Unmanaged<CURL>.fromOpaque(COpaquePointer(p)).takeUnretainedValue()
			return 0
		}
		setOption(CURLOPT_READFUNCTION, f: readFunc)
		
	}
	
	/// Clean up and reset the CURL object.
	public func reset() {
		if curl != nil {
			if multi != nil {
				curl_multi_remove_handle(multi!, curl!)
				multi = nil
			}
			while slists.count > 0 {
				curl_slist_free_all(slists.last!)
				slists.removeLast()
			}
			curl_easy_reset(curl!)
			setCurlOpts()
		}
	}
	
	/// Perform the CURL request in a non-blocking manner. The closure will be called with the resulting code, header and body data.
	public func perform(closure: (Int, [UInt8], [UInt8]) -> ()) {
		
		let header = Bytes()
		let body = Bytes()
		
		multi = curl_multi_init()
		curl_multi_add_handle(multi!, curl!)
		
		performInner(header, body: body, closure: closure)
	}
	
	private func performInner(header: Bytes, body: Bytes, closure: (Int, [UInt8], [UInt8]) -> ()) {
		let perf = perform()
		if let h = perf.2 {
			header.importBytes(h)
		} 
		if let b = perf.3 {
			body.importBytes(b)
		}
		if perf.0 == false { // done
			closure(perf.1, header.data, body.data)
		} else {
			Threading.dispatchBlock {
				self.performInner(header, body: body, closure: closure)
			}
		}
	}
	
	/// Performs the request, blocking the current thread until it completes.
	/// - returns: A tuple consisting of: Int - the result code, [UInt8] - the header bytes if any, [UInt8] - the body bytes if any
	public func performFully() -> (Int, [UInt8], [UInt8]) {
		
		let code = curl_easy_perform(curl!)
		defer {
			if headerBytes.count > 0 {
				headerBytes = [UInt8]()
			}
			if bodyBytes.count > 0 {
				bodyBytes = [UInt8]()
			}
			reset()
		}
		if code != CURLE_OK {
			let str = strError(code)
			print(str)
		}
		return (Int(code.rawValue), headerBytes, bodyBytes)
	}
	
	/// Performs a bit of work on the current request.
	/// - returns: A tuple consisting of: Bool - should perform() be called again, Int - the result code, [UInt8] - the header bytes if any, [UInt8] - the body bytes if any
	public func perform() -> (Bool, Int, [UInt8]?, [UInt8]?) {
		if multi == nil {
			multi = curl_multi_init()
			curl_multi_add_handle(multi!, curl!)
		}
		var one: Int32 = 0
		var code = CURLM_OK
		repeat {
		
			code = curl_multi_perform(multi!, &one)
			
		} while code == CURLM_CALL_MULTI_PERFORM
		
		guard code == CURLM_OK else {
			return (false, Int(code.rawValue), nil, nil)
		}
		var two: Int32 = 0
		let msg = curl_multi_info_read(multi!, &two)
		
		defer {
			if headerBytes.count > 0 {
				headerBytes = [UInt8]()
			}
			if bodyBytes.count > 0 {
				bodyBytes = [UInt8]()
			}
		}
		
		if msg != nil {
			let msgResult = curl_get_msg_result(msg)
			guard msgResult == CURLE_OK else {
				return (false, Int(msgResult.rawValue), nil, nil)
			}
			return (false, Int(msgResult.rawValue),
				headerBytes.count > 0 ? headerBytes : nil,
				bodyBytes.count > 0 ? bodyBytes : nil)
		}
		return (true, 0,
			headerBytes.count > 0 ? headerBytes : nil,
			bodyBytes.count > 0 ? bodyBytes : nil)
	}
	
//	/// Returns the result code for the last
//	public func multiResult() -> CURLcode {
//		var two: Int32 = 0
//		let msg = curl_multi_info_read(multi!, &two)
//		if msg != nil && msg.memory.msg == CURLMSG_DONE {
//			return curl_get_msg_result(msg)
//		}
//		return CURLE_OK
//	}
	
	/// Returns the String message for the given CURL result code.
	public func strError(code: CURLcode) -> String {
		return String.fromCString(curl_easy_strerror(code))!
	}
	
	/// Returns the Int value for the given CURLINFO.
	public func getInfo(info: CURLINFO) -> (Int, CURLcode) {
		var i = 0
		let c = curl_easy_getinfo_long(curl!, info, &i)
		return (i, c)
	}
	
	/// Returns the String value for the given CURLINFO.
	public func getInfo(info: CURLINFO) -> (String, CURLcode) {
		let i = UnsafeMutablePointer<UnsafePointer<Int8>>.alloc(1)
		defer { i.destroy(); i.dealloc(1) }
		let code = curl_easy_getinfo_cstr(curl!, info, i)
		return (code != CURLE_OK ? "" : String.fromCString(i.memory)!, code)
	}
	
	/// Sets the Int64 option value.
	public func setOption(option: CURLoption, int: Int64) -> CURLcode {
		return curl_easy_setopt_int64(curl!, option, int)
	}
	
	/// Sets the Int option value.
	public func setOption(option: CURLoption, int: Int) -> CURLcode {
		return curl_easy_setopt_long(curl!, option, int)
	}
	
	/// Sets the poionter option value.
	public func setOption(option: CURLoption, v: UnsafeMutablePointer<Void>) -> CURLcode {
		return curl_easy_setopt_void(curl!, option, v)
	}
	
	/// Sets the callback function option value.
	public func setOption(option: CURLoption, f: curl_func) -> CURLcode {
		return curl_easy_setopt_func(curl!, option, f)
	}
	
	/// Sets the String option value.
	public func setOption(option: CURLoption, s: String) -> CURLcode {
		switch(option.rawValue) {
		case CURLOPT_HTTP200ALIASES.rawValue,
			CURLOPT_HTTPHEADER.rawValue,
			CURLOPT_POSTQUOTE.rawValue,
			CURLOPT_PREQUOTE.rawValue,
			CURLOPT_QUOTE.rawValue,
			CURLOPT_MAIL_FROM.rawValue,
			CURLOPT_MAIL_RCPT.rawValue:
			let slist = curl_slist_append(nil, s)
			slists.append(slist)
			return curl_easy_setopt_slist(curl!, option, slist)
		default:
			()
		}
		return curl_easy_setopt_cstr(curl!, option, s)
	}
	
	/// Cleanup and close the CURL request.
	public func close() {
		if curl != nil {
			if multi != nil {
				curl_multi_cleanup(multi!)
				multi = nil
			}
			curl_easy_cleanup(curl!)
			
			curl = nil
			while slists.count > 0 {
				curl_slist_free_all(slists.last!)
				slists.removeLast()
			}
		}
	}
	
	deinit {
		close()
	}
}

