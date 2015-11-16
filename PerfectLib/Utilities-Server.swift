//
//  Utilities-Server.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2015-10-19.
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

