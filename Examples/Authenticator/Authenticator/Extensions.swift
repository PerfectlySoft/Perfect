//
//  Extensions.swift
//  Authenticator
//
//  Created by Kyle Jessup on 2015-11-10.
//  Copyright © 2015 PerfectlySoft. All rights reserved.
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

#if os(OSX)
import CommonCrypto
#else
import OpenSSL
#endif

extension String {
	public var md5: [UInt8] {
#if os(Linux)
		let bytes = UnsafeMutablePointer<UInt8>.alloc(Int(MD5_DIGEST_LENGTH))
		defer { bytes.destroy() ; bytes.dealloc(Int(MD5_DIGEST_LENGTH)) }
		
		MD5(Array<UInt8>(self.utf8), (self.utf8.count), bytes)
		
		var r = [UInt8]()
		for idx in 0..<Int(MD5_DIGEST_LENGTH) {
			r.append(bytes[idx])
		}
#else
		let bytes = UnsafeMutablePointer<UInt8>.alloc(Int(CC_MD5_DIGEST_LENGTH))
		defer { bytes.destroy() ; bytes.dealloc(Int(CC_MD5_DIGEST_LENGTH)) }
		
		CC_MD5(Array<UInt8>(self.utf8), CC_LONG(self.utf8.count), bytes)
		
		var r = [UInt8]()
		for idx in 0..<Int(CC_MD5_DIGEST_LENGTH) {
			r.append(bytes[idx])
		}
#endif
		return r
	}
}

func toHex(a: [UInt8]) -> String {
	var s = ""
	for i8 in a {
		let b = i8 >> 4
		s.append(UnicodeScalar(b > 9 ? b - 10 + 65 : b + 48))
		
		let b2 = i8 & 0x0F
		s.append(UnicodeScalar(b2 > 9 ? b2 - 10 + 65 : b2 + 48))
	}
	return s.lowercaseString
}
