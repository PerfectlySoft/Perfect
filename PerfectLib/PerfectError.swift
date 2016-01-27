//
//  PerfectError.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/5/15.
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
