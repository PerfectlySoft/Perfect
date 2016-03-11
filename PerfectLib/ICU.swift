//
//  ICU.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/14/15.
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

import ICU

/// This class provides a series of class functions which expose some of the ICU
/// library's functionality
public class ICU {
	
	/// Returns true if the UnicodeScalar is a white space character
	public static func isWhiteSpace(e: UnicodeScalar) -> Bool {
		return 1 == u_isWhitespace_wrapper(UChar32(e.value))
	}
	/// Returns true if the UnicodeScalar is a digit character
	public static func isDigit(e: UnicodeScalar) -> Bool {
		return 1 == u_isdigit_wrapper(UChar32(e.value))
	}
	/// Returns true if the UnicodeScalar is an alpha-numeric character
	public static func isAlphaNum(e: UnicodeScalar) -> Bool {
		return 1 == u_isalnum_wrapper(UChar32(e.value))
	}
	/// Returns true if the UnicodeScalar is a hexadecimal character
	public static func isHexDigit(e: UnicodeScalar) -> Bool {
		if isDigit(e) {
			return true
		}
		switch e {
		case "A", "B", "C", "D", "E", "F", "a", "b", "c", "d", "e", "f":
			return true
		default:
			return false
		}
	}
	/// Returns the current time according to ICU
	/// ICU dates are the number of milliseconds since the reference date of Thu, 01-Jan-1970 00:00:00 GMT
	public static func getNow() -> Double {
		return ucal_getNow_wrapper()
	}
	/// Converts the milliseconds based ICU date to seconds since the epoch
	public static func icuDateToSeconds(icuDate: Double) -> Int {
		return Int(icuDate / 1000)
	}
	/// Converts the seconds since the epoch into the milliseconds based ICU date
	public static func secondsToICUDate(seconds: Int) -> Double {
		return Double(seconds * 1000)
	}
	
	static func U_SUCCESS(status: UErrorCode) -> Bool {
		return status.rawValue <= U_ZERO_ERROR.rawValue
	}
	
	@noreturn
	static func ThrowICUError(code: UErrorCode) throws {
		let msg = String.fromCString(u_errorName_wrapper(code))!
		
		print("ICUError: \(code.rawValue) \(msg)")
		
		throw PerfectError.SystemError(code.rawValue, msg)
	}
	
	/// Parse a date string according to the indicated format string and return an ICU date.
	/// - parameter dateStr: The date string
	/// - parameter format: The format by which the date string will be parsed
	/// - parameter timezone: The optional timezone in which the date is expected to be based. Default is the local timezone.
	/// - parameter locale: The optional locale which will be used when parsing the date. Default is the current global locale.
	/// - returns: The resulting date
	/// - throws: `PerfectError.ICUError`
	/// - Seealso [Date Time Format Syntax](http://userguide.icu-project.org/formatparse/datetime#TOC-Date-Time-Format-Syntax)
	public static func parseDate(dateStr: String, format: String, timezone inTimezone: String? = nil, locale inLocale: String? = nil) throws -> Double {
		var status = UErrorCode(0)
		let utf16Chars = format.utf16
		var locale = UnsafePointer<Int8>(())
		var timezone = UnsafeMutablePointer<UInt16>(())
		var timeZoneLength: Int32 = 0
		
		if let tz = inTimezone {
			let tzUtf16 = tz.utf16
			timezone = UnsafeMutablePointer<UInt16>(Array<UInt16>(tzUtf16))
			timeZoneLength = Int32(tzUtf16.count)
		}
		
		if let loc = inLocale {
			let utf8Chars = loc.utf8
			locale = UnsafePointer<Int8>(Array<UInt8>(utf8Chars))
		}
		
		let dateFormat = udat_open_wrapper(UDAT_PATTERN, UDAT_PATTERN, locale, timezone, timeZoneLength, Array<UInt16>(utf16Chars), Int32(utf16Chars.count), &status)
		
		guard U_SUCCESS(status) else {
			try ThrowICUError(status)
		}
		
		defer { udat_close_wrapper(dateFormat) }
		
		let srcUtf16Chars = dateStr.utf16
		let date = udat_parse_wrapper(dateFormat, Array<UInt16>(srcUtf16Chars), Int32(srcUtf16Chars.count), nil, &status)
		
		guard U_SUCCESS(status) else {
			try ThrowICUError(status)
		}
		
		return date
	}
	
	/// Format a date value according to the indicated format string and return a date string.
	/// - parameter date: The date value
	/// - parameter format: The format by which the date will be formatted
	/// - parameter timezone: The optional timezone in which the date is expected to be based. Default is the local timezone.
	/// - parameter locale: The optional locale which will be used when parsing the date. Default is the current global locale.
	/// - returns: The resulting date string
	/// - throws: `PerfectError.ICUError`
	/// - Seealso [Date Time Format Syntax](http://userguide.icu-project.org/formatparse/datetime#TOC-Date-Time-Format-Syntax)
	public static func formatDate(date: Double, format: String, timezone inTimezone: String? = nil, locale inLocale: String? = nil) throws -> String {
		var status = UErrorCode(0)
		let utf16Chars = format.utf16
		var locale = UnsafePointer<Int8>(())
		var timezone = UnsafeMutablePointer<UInt16>(())
		var timeZoneLength: Int32 = 0
		
		if let tz = inTimezone {
			let tzUtf16 = tz.utf16
			timezone = UnsafeMutablePointer<UInt16>(Array<UInt16>(tzUtf16))
			timeZoneLength = Int32(tzUtf16.count)
		}
		
		if let loc = inLocale {
			let utf8Chars = loc.utf8
			locale = UnsafePointer<Int8>(Array<UInt8>(utf8Chars))
		}
		
		let dateFormat = udat_open_wrapper(UDAT_PATTERN, UDAT_PATTERN, locale, timezone, timeZoneLength, Array<UInt16>(utf16Chars), Int32(utf16Chars.count), &status)
		
		guard U_SUCCESS(status) else {
			try ThrowICUError(status)
		}
		
		defer { udat_close_wrapper(dateFormat) }
		
		let buffer = UnsafeMutablePointer<UInt16>.alloc(1024)
		defer { buffer.destroy() ; buffer.dealloc(1024) }
		let formatResult = udat_format_wrapper(dateFormat, date, buffer, 1024, nil, &status)
		
		guard formatResult > 0 && U_SUCCESS(status) else {
			try ThrowICUError(status)
		}
		
		let res = Encoding.encode(UTF16(), generator: GenerateFromPointer(from: buffer, count: Int(formatResult)))
		
		return res
	}
}







