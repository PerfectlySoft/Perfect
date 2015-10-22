//
//  PerfectError.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/5/15.
//
//

import Foundation

/// Some but not all of the exception types which may be thrown by the system
public enum PerfectError : ErrorType {
	case NetworkError(Int32, String)
	case FileError(Int32, String)
	case SystemError(Int32, String)
	case APIError(String)
}

@noreturn
func ThrowFileError() throws {
	let err = errno
	let msg = String.fromCString(strerror(err))!
	
	print("FileError: \(err) \(msg)")
	
	throw PerfectError.FileError(err, msg)
}

@noreturn
func ThrowSystemError() throws {
	let err = errno
	let msg = String.fromCString(strerror(err))!
	
	print("SystemError: \(err) \(msg)")
	
	throw PerfectError.SystemError(err, msg)
}

@noreturn
func ThrowNetworkError() throws {
	let err = errno
	let msg = String.fromCString(strerror(err))!
	
	print("NetworkError: \(err) \(msg)")
	
	throw PerfectError.NetworkError(err, msg)
}
