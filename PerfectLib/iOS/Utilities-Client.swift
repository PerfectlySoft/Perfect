//
//  Utilities-Client.swift
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


extension UnicodeScalar {
	
	static private let letters = NSCharacterSet.letterCharacterSet()
	static private let digits = NSCharacterSet.decimalDigitCharacterSet()
	static private let spaces = NSCharacterSet.whitespaceAndNewlineCharacterSet()
	
	/// Returns true if the UnicodeScalar is a white space character
	public func isWhiteSpace() -> Bool {
		return UnicodeScalar.spaces.longCharacterIsMember(self.value)
	}
	/// Returns true if the UnicodeScalar is a digit character
	public func isDigit() -> Bool {
		return UnicodeScalar.digits.longCharacterIsMember(self.value)
	}
	/// Returns true if the UnicodeScalar is an alpha-numeric character
	public func isAlphaNum() -> Bool {
		return UnicodeScalar.letters.longCharacterIsMember(self.value) || UnicodeScalar.digits.longCharacterIsMember(self.value)
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

