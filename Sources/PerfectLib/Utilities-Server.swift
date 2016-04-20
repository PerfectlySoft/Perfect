//
//  Utilities-Server.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2015-10-19.
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
#else
import Darwin
#endif

extension UnicodeScalar {

	/// Returns true if the UnicodeScalar is a white space character
	public func isWhiteSpace() -> Bool {
		return isspace(Int32(self.value)) != 0
	}
	/// Returns true if the UnicodeScalar is a digit character
	public func isDigit() -> Bool {
		return isdigit(Int32(self.value)) != 0
	}
	/// Returns true if the UnicodeScalar is an alpha-numeric character
	public func isAlphaNum() -> Bool {
		return isalnum(Int32(self.value)) != 0
	}
	/// Returns true if the UnicodeScalar is a hexadecimal character
	public func isHexDigit() -> Bool {
		if self.isDigit() {
			return true
		}
		switch self {
		case "A", "B", "C", "D", "E", "F", "a", "b", "c", "d", "e", "f":
			return true
		default:
			return false
		}
	}
}
