//
//  Utilities-Server.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2015-10-19.
//  Copyright © 2015 PerfectlySoft. All rights reserved.
//

extension UnicodeScalar {

	/// Returns true if the UnicodeScalar is a white space character
	public func isWhiteSpace() -> Bool {
		return ICU.isWhiteSpace(self)
	}
	/// Returns true if the UnicodeScalar is a digit character
	public func isDigit() -> Bool {
		return ICU.isDigit(self)
	}
	/// Returns true if the UnicodeScalar is an alpha-numeric character
	public func isAlphaNum() -> Bool {
		return ICU.isAlphaNum(self)
	}
	/// Returns true if the UnicodeScalar is a hexadecimal character
	public func isHexDigit() -> Bool {
		return ICU.isHexDigit(self)
	}
}

