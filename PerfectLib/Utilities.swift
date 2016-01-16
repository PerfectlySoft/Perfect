//
//  Utilities.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/17/15.
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

import Foundation

/// This class permits an UnsafeMutablePointer to be used as a GeneratorType
public struct GenerateFromPointer<T> : GeneratorType {
	
	public typealias Element = T
	
	var count = 0
	var pos = 0
	var from: UnsafeMutablePointer<T>
	
	/// Initialize given an UnsafeMutablePointer and the number of elements pointed to.
	public init(from: UnsafeMutablePointer<T>, count: Int) {
		self.from = from
		self.count = count
	}
	
	/// Return the next element or nil if the sequence has been exhausted.
	mutating public func next() -> Element? {
		guard count > 0 else {
			return nil
		}
		self.count -= 1
		return self.from[self.pos++]
	}
}

/// A generalized wrapper around the Unicode codec operations.
public class Encoding {
	
	/// Return a String given a character generator.
	public static func encode<D : UnicodeCodecType, G : GeneratorType where G.Element == D.CodeUnit>(decoder : D, generator: G) -> String {
		var encodedString = ""
		var finished: Bool = false
		var mutableDecoder = decoder
		var mutableGenerator = generator
		repeat {
			let decodingResult = mutableDecoder.decode(&mutableGenerator)
			switch decodingResult {
			case .Result(let char):
				encodedString.append(char)
			case .EmptyInput:
				finished = true
				/* ignore errors and unexpected values */
			case .Error:
				finished = true
			}
		} while !finished
		return encodedString
	}
}

/// Utility wrapper permitting a UTF-16 character generator to encode a String.
public class UTF16Encoding {
	
	/// Use a UTF-16 character generator to create a String.
	public static func encode<G : GeneratorType where G.Element == UTF16.CodeUnit>(generator: G) -> String {
		return Encoding.encode(UTF16(), generator: generator)
	}
}

/// Utility wrapper permitting a UTF-8 character generator to encode a String. Also permits a String to be converted into a UTF-8 byte array.
public class UTF8Encoding {
	
	/// Use a character generator to create a String.
	public static func encode<G : GeneratorType where G.Element == UTF8.CodeUnit>(generator: G) -> String {
		return Encoding.encode(UTF8(), generator: generator)
	}
	
	/// Use a character sequence to create a String.
	public static func encode<S : SequenceType where S.Generator.Element == UTF8.CodeUnit>(bytes: S) -> String {
		return encode(bytes.generate())
	}
	
	/// Decode a String into an array of UInt8.
	public static func decode(str: String) -> Array<UInt8> {
		return Array<UInt8>(str.utf8)
	}
}

extension UInt8 {
	private var shouldURLEncode: Bool {
		let cc = self
		return ( ( cc >= 128 )
			|| ( cc < 33 )
			|| ( cc >= 34  && cc < 38 )
			|| ( ( cc > 59  && cc < 61) || cc == 62 || cc == 58)
			|| ( ( cc >= 91  && cc < 95 ) || cc == 96 )
			|| ( cc >= 123 && cc <= 126 )
			|| self == 43 )
	}
	private var hexString: String {
		var s = ""
		let b = self >> 4
		s.append(UnicodeScalar(b > 9 ? b - 10 + 65 : b + 48))
		let b2 = self & 0x0F
		s.append(UnicodeScalar(b2 > 9 ? b2 - 10 + 65 : b2 + 48))
		return s
	}
}

extension String {
	/// Returns the String with all special HTML characters encoded.
	public var stringByEncodingHTML: String {
		var ret = ""
		var g = self.unicodeScalars.generate()
		while let c = g.next() {
			if c < UnicodeScalar(0x0009) {
				ret.appendContentsOf("&#x");
				ret.append(UnicodeScalar(0x0030 + UInt32(c)));
				ret.appendContentsOf(";");
			} else if c == UnicodeScalar(0x0022) {
				ret.appendContentsOf("&quot;")
			} else if c == UnicodeScalar(0x0026) {
				ret.appendContentsOf("&amp;")
			} else if c == UnicodeScalar(0x0027) {
				ret.appendContentsOf("&#39;")
			} else if c == UnicodeScalar(0x003C) {
				ret.appendContentsOf("&lt;")
			} else if c == UnicodeScalar(0x003E) {
				ret.appendContentsOf("&gt;")
			} else if c > UnicodeScalar(126) {
				ret.appendContentsOf("&#\(UInt32(c));")
			} else {
				ret.append(c)
			}
		}
		return ret
	}
	
	/// Returns the String with all special URL characters encoded.
	public var stringByEncodingURL: String {
		var ret = ""
		var g = self.utf8.generate()
		while let c = g.next() {
			if c.shouldURLEncode {
				ret.append(UnicodeScalar(37))
				ret.appendContentsOf(c.hexString)
			} else {
				ret.append(UnicodeScalar(c))
			}
		}
		return ret
	}
	
	public var stringByDecodingURL: String? {
		
		let percent: UInt8 = 37
		let plus: UInt8 = 43
		let capA: UInt8 = 65
		let capF: UInt8 = 70
		let lowA: UInt8 = 97
		let lowF: UInt8 = 102
		let zero: UInt8 = 48
		let nine: UInt8 = 57
		let space: UInt8 = 32
		
		var bytesArray = [UInt8]()
		
		var g = self.utf8.generate()
		while let c = g.next() {
			if c == percent {
				var newChar = UInt8(0)
				
				guard let c1v = g.next() else {
					return nil
				}
				guard let c2v = g.next() else {
					return nil
				}
				
				if c1v >= capA && c1v <= capF {
					newChar = c1v - capA + 10
				} else if c1v >= lowA && c1v <= lowF {
					newChar = c1v - lowA + 10
				} else if c1v >= zero && c1v <= nine {
					newChar = c1v - zero
				} else {
					return nil
				}
				
				newChar *= 16
				
				if c2v >= capA && c2v <= capF {
					newChar += c2v - capA + 10
				} else if c2v >= lowA && c2v <= lowF {
					newChar += c2v - lowA + 10
				} else if c2v >= zero && c2v <= nine {
					newChar += c2v - zero
				} else {
					return nil
				}
				
				bytesArray.append(newChar)
			} else if c == plus {
				bytesArray.append(space)
			} else {
				bytesArray.append(c)
			}
		}
		
		return UTF8Encoding.encode(bytesArray)
	}
}

extension String {
	
	/// Parse an HTTP Digest authentication header returning a Dictionary containing each part.
	public func parseAuthentication() -> [String:String] {
		var ret = [String:String]()
		if let _ = self.rangeOf("Digest ") {
			ret["type"] = "Digest"
			let wantFields = ["username", "nonce", "nc", "cnonce", "response", "uri", "realm", "qop", "algorithm"]
			for field in wantFields {
				if let foundField = String.extractField(self, named: field) {
					ret[field] = foundField
				}
			}
		}
		return ret
	}
	
	private static func extractField(from: String, named: String) -> String? {
		guard let range = from.rangeOf(named + "=") else {
			return nil
		}
		
		var currPos = range.endIndex
		var ret = ""
		let quoted = from[currPos] == "\""
		if quoted {
			currPos = currPos.successor()
			let tooFar = from.endIndex
			while currPos != tooFar {
				if from[currPos] == "\"" {
					break
				}
				ret.append(from[currPos])
				currPos = currPos.successor()
			}
		} else {
			let tooFar = from.endIndex
			while currPos != tooFar {
				if from[currPos] == "," {
					break
				}
				ret.append(from[currPos])
				currPos = currPos.successor()
			}
		}
		return ret
	}
}

extension String {
	
	public func stringByReplacingString(find: String, withString: String) -> String {
		
		guard !find.isEmpty else {
			return self
		}
		guard !self.isEmpty else {
			return self
		}
		
		var ret = ""
		var idx = self.startIndex
		let endIdx = self.endIndex
		
		while idx != endIdx {
			if self[idx] == find[find.startIndex] {
				var newIdx = idx.advancedBy(1)
				var findIdx = find.startIndex.advancedBy(1)
				let findEndIdx = find.endIndex
				
				while newIdx != endIndex && findIdx != findEndIdx && self[newIdx] == find[findIdx] {
					newIdx = newIdx.advancedBy(1)
					findIdx = findIdx.advancedBy(1)
				}
				
				if findIdx == findEndIdx { // match
					ret.appendContentsOf(withString)
					idx = newIdx
					continue
				}
			}
			ret.append(self[idx])
			idx = idx.advancedBy(1)
		}
		
		return ret
	}
	
	public func substringTo(index: String.Index) -> String {
		var s = ""
		var idx = self.startIndex
		let endIdx = self.endIndex
		while idx != endIdx && idx != index {
			s.append(self[idx])
			idx = idx.successor()
		}
		return s
	}
	
	public func substringWith(range: Range<String.Index>) -> String {
		var s = ""
		var idx = range.startIndex
		let endIdx = self.endIndex
		
		while idx < endIdx && idx < range.endIndex {
			s.append(self[idx])
			idx = idx.successor()
		}
		
		return s
	}
	
	public func rangeOf(string: String, ignoreCase: Bool = false) -> Range<String.Index>? {
		var idx = self.startIndex
		let endIdx = self.endIndex
		
		while idx != endIdx {
			if ignoreCase ? (String(self[idx]).lowercaseString == String(string[string.startIndex]).lowercaseString) : (self[idx] == string[string.startIndex]) {
				var newIdx = idx.advancedBy(1)
				var findIdx = string.startIndex.advancedBy(1)
				let findEndIdx = string.endIndex
				
				while newIdx != endIndex && findIdx != findEndIdx && (ignoreCase ? (String(self[newIdx]).lowercaseString == String(string[findIdx]).lowercaseString) : (self[newIdx] == string[findIdx])) {
					newIdx = newIdx.advancedBy(1)
					findIdx = findIdx.advancedBy(1)
				}
				
				if findIdx == findEndIdx { // match
					return Range(start: idx, end: newIdx)
				}
			}
			idx = idx.advancedBy(1)
		}
		return nil
	}

	public func contains(string: String) -> Bool {
		return nil != self.rangeOf(string)
	}
}

extension String {
	
	var pathSeparator: UnicodeScalar {
		return UnicodeScalar(47)
	}
	
	var extensionSeparator: UnicodeScalar {
		return UnicodeScalar(46)
	}
	
	private var beginsWithSeparator: Bool {
		let unis = self.characters
		guard unis.count > 0 else {
			return false
		}
		return unis[unis.startIndex] == Character(pathSeparator)
	}
	
	private var endsWithSeparator: Bool {
		let unis = self.characters
		guard unis.count > 0 else {
			return false
		}
		return unis[unis.endIndex.predecessor()] == Character(pathSeparator)
	}
	
	private func pathComponents(addFirstLast: Bool) -> [String] {
		var r = [String]()
		let unis = self.characters
		guard unis.count > 0 else {
			return r
		}
		
		if addFirstLast && self.beginsWithSeparator {
			r.append(String(pathSeparator))
		}
		
		r.appendContentsOf(self.characters.split(Character(pathSeparator)).map { String($0) })
		
		if addFirstLast && self.endsWithSeparator {
			if !self.beginsWithSeparator || r.count > 1 {
				r.append(String(pathSeparator))
			}
		}
		return r
	}
	
	var pathComponents: [String] {
		return self.pathComponents(true)
	}
	
	var lastPathComponent: String {
		let last = self.pathComponents(false).last ?? ""
		if last.isEmpty && self.characters.first == Character(pathSeparator) {
			return String(pathSeparator)
		}
		return last
	}
	
	var stringByDeletingLastPathComponent: String {
		var comps = self.pathComponents(false)
		guard comps.count > 1 else {
			if self.beginsWithSeparator {
				return String(pathSeparator)
			}
			return ""
		}
		comps.removeLast()
		let joined = comps.joinWithSeparator(String(pathSeparator))
		if self.beginsWithSeparator {
			return String(pathSeparator) + joined
		}
		return joined
	}
	
	var stringByDeletingPathExtension: String {
		let unis = self.characters
		let startIndex = unis.startIndex
		var endIndex = unis.endIndex
		while endIndex != startIndex {
			if unis[endIndex.predecessor()] != Character(pathSeparator) {
				break
			}
			endIndex = endIndex.predecessor()
		}
		let noTrailsIndex = endIndex
		while endIndex != startIndex {
			endIndex = endIndex.predecessor()
			if unis[endIndex] == Character(extensionSeparator) {
				break
			}
		}
		guard endIndex != startIndex else {
			if noTrailsIndex == startIndex {
				return self
			}
			return self.substringTo(noTrailsIndex)
		}
		return self.substringTo(endIndex)
	}
	
	var pathExtension: String {
		let unis = self.characters
		let startIndex = unis.startIndex
		var endIndex = unis.endIndex
		while endIndex != startIndex {
			if unis[endIndex.predecessor()] != Character(pathSeparator) {
				break
			}
			endIndex = endIndex.predecessor()
		}
		let noTrailsIndex = endIndex
		while endIndex != startIndex {
			endIndex = endIndex.predecessor()
			if unis[endIndex] == Character(extensionSeparator) {
				break
			}
		}
		guard endIndex != startIndex else {
			return ""
		}
		return self.substringWith(Range(start:endIndex.successor(), end:noTrailsIndex))
	}

	var stringByResolvingSymlinksInPath: String {
		return File(self).realPath()
		
//		let absolute = self.beginsWithSeparator
//		let components = self.pathComponents(false)
//		var s = absolute ? "/" : ""
//		for component in components {
//			if component == "." {
//				s.appendContentsOf(".")
//			} else if component == ".." {
//				s.appendContentsOf("..")
//			} else {
//				let file = File(s + "/" + component)
//				s = file.realPath()
//			}
//		}
//		let ary = s.pathComponents(false) // get rid of slash runs
//		return absolute ? "/" + ary.joinWithSeparator(String(pathSeparator)) : ary.joinWithSeparator(String(pathSeparator))
	}
	
	
}
















