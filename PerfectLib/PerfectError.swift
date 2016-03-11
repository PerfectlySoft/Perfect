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
import LinuxBridge

var errno: Int32 {
	return linux_errno()
}
#else
import Darwin
#endif

/// Some but not all of the exception types which may be thrown by the system
public enum PerfectError : ErrorType {
	/// A network related error code and message.
	case NetworkError(Int32, String)
	/// A file system related error code and message.
	case FileError(Int32, String)
	/// A OS level error code and message.
	case SystemError(Int32, String)
	/// An API exception error message.
	case APIError(String)
}

@noreturn
func ThrowFileError() throws {
	let err = errno
	let msg = String.fromCString(strerror(err))!
	
//	print("FileError: \(err) \(msg)")
	
	throw PerfectError.FileError(err, msg)
}

@noreturn
func ThrowSystemError() throws {
	let err = errno
	let msg = String.fromCString(strerror(err))!
	
//	print("SystemError: \(err) \(msg)")
	
	throw PerfectError.SystemError(err, msg)
}

@noreturn
func ThrowNetworkError() throws {
	let err = errno
	let msg = String.fromCString(strerror(err))!
	
//	print("NetworkError: \(err) \(msg)")
	
	throw PerfectError.NetworkError(err, msg)
}
