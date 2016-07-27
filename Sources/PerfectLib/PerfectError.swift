//
//  PerfectError.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/5/15.
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

#if os(Linux)
import SwiftGlibc

var errno: Int32 {
	return __errno_location().pointee
}
#else
import Darwin
#endif

/// Some but not all of the exception types which may be thrown by the system
public enum PerfectError : Error {
	/// A network related error code and message.
	case networkError(Int32, String)
	/// A file system related error code and message.
	case fileError(Int32, String)
	/// A OS level error code and message.
	case systemError(Int32, String)
	/// An API exception error message.
	case apiError(String)
}


func ThrowFileError(file: String = #file, function: String = #function, line: Int = #line) throws -> Never  {
	let err = errno
	let msg = String(validatingUTF8: strerror(err))!
	
//	print("FileError: \(err) \(msg)")
	
	throw PerfectError.fileError(err, msg + " \(file) \(function) \(line)")
}


func ThrowSystemError(file: String = #file, function: String = #function, line: Int = #line) throws -> Never  {
	let err = errno
	let msg = String(validatingUTF8: strerror(err))!
	
//	print("SystemError: \(err) \(msg)")
	
	throw PerfectError.systemError(err, msg + " \(file) \(function) \(line)")
}


func ThrowNetworkError(file: String = #file, function: String = #function, line: Int = #line) throws -> Never  {
	let err = errno
	let msg = String(validatingUTF8: strerror(err))!
	
//	print("NetworkError: \(err) \(msg)")
	
	throw PerfectError.networkError(err, msg + " \(file) \(function) \(line)")
}
