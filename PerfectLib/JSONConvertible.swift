//
//  JSONConvertible.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2016-01-21.
//  Copyright © 2016 Treefrog. All rights reserved.
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

/// This non-instantiable object serves as an access point to a registry for JSONConvertibleObjects
/// A JSONConvertibleObject is a custom class or struct which can be converted to and from JSON.
public class JSONDecoding {
	private init() {}
	
	public static let objectIdentifierKey = "_jsonobjid"
	public typealias JSONConvertibleObjectCreator = () -> JSONConvertibleObject
	
	static private var jsonDecodableRegistry = [String:JSONConvertibleObjectCreator]()
	
	static public func registerJSONDecodable(name: String, creator: JSONConvertibleObjectCreator) {
		JSONDecoding.jsonDecodableRegistry[name] = creator
	}
	
	static public func createJSONConvertibleObject(values:[String:Any]) -> JSONConvertibleObject? {
		guard let objkey = values[JSONDecoding.objectIdentifierKey] as? String else {
			return nil
		}
		return JSONDecoding.createJSONConvertibleObject(objkey, values: values)
	}
	
	static public func createJSONConvertibleObject(name: String, values:[String:Any]) -> JSONConvertibleObject? {
		guard let creator = JSONDecoding.jsonDecodableRegistry[name] else {
			return nil
		}
		let jsonObj = creator()
		jsonObj.setJSONValues(values)
		return jsonObj
	}
}

public protocol JSONConvertible {
	
	/// Returns the JSON encoded String for any JSONConvertible type.
	func jsonEncodedString() throws -> String
}

// changed this to be a class due to Linux protocols failing 'as' tests
public class JSONConvertibleObject: JSONConvertible {
	
	public init() {}
	
	public func setJSONValues(values:[String:Any]) {}
	public func getJSONValues() -> [String:Any] { return [String:Any]() }

	public func jsonEncodedString() throws -> String {
		return try self.getJSONValues().jsonEncodedString()
	}
}

public extension JSONConvertibleObject {
	func getJSONValue<T: JSONConvertible>(named: String, from:[String:Any], defaultValue: T) -> T {
		let f = from[named]
		if let v = f as? T {
			return v
		}
		return defaultValue
	}
//	func jsonEncodedString() throws -> String {
//		return try self.getJSONValues().jsonEncodedString()
//	}
}

public enum JSONConversionError: ErrorType {
	case NotConvertible(Any)
	case InvalidKey(Any)
	case SyntaxError
}

private let jsonBackSlash = UnicodeScalar(UInt32(92))
private let jsonBackSpace = UnicodeScalar(UInt32(8))
private let jsonFormFeed = UnicodeScalar(UInt32(12))
private let jsonLF = UnicodeScalar(UInt32(10))
private let jsonCR = UnicodeScalar(UInt32(13))
private let jsonTab = UnicodeScalar(UInt32(9))
private let jsonQuoteDouble = UnicodeScalar(UInt32(34))

private let jsonOpenObject = UnicodeScalar(UInt32(123))
private let jsonOpenArray = UnicodeScalar(UInt32(91))
private let jsonCloseObject = UnicodeScalar(UInt32(125))
private let jsonCloseArray = UnicodeScalar(UInt32(93))
private let jsonWhiteSpace = UnicodeScalar(UInt32(32))
private let jsonColon = UnicodeScalar(UInt32(58))
private let jsonComma = UnicodeScalar(UInt32(44))

// this is a stand-in for a JSON null
// may be produced when decoding
public struct JSONConvertibleNull: JSONConvertible {
	public func jsonEncodedString() throws -> String {
		return "null"
	}
}

extension String: JSONConvertible {
	public func jsonEncodedString() throws -> String {
		var s = "\""
		for uchar in self.unicodeScalars {
			switch(uchar) {
			case jsonBackSlash:
				s.appendContentsOf("\\\\")
			case jsonQuoteDouble:
				s.appendContentsOf("\\\"")
			case jsonBackSpace:
				s.appendContentsOf("\\b")
			case jsonFormFeed:
				s.appendContentsOf("\\f")
			case jsonLF:
				s.appendContentsOf("\\n")
			case jsonCR:
				s.appendContentsOf("\\r")
			case jsonTab:
				s.appendContentsOf("\\t")
			default:
				s.append(uchar)
			}
		}
		s.appendContentsOf("\"")
		return s
	}
}

extension Int: JSONConvertible {
	public func jsonEncodedString() throws -> String {
		return String(self)
	}
}

extension UInt: JSONConvertible {
	public func jsonEncodedString() throws -> String {
		return String(self)
    }
}

extension Double: JSONConvertible {
	public func jsonEncodedString() throws -> String {
		return String(self)
	}
}

extension Optional: JSONConvertible {
	public func jsonEncodedString() throws -> String {
		if self == nil {
			return "null"
		} else if let v = self! as? JSONConvertible {
			return try v.jsonEncodedString()
		}
		throw JSONConversionError.NotConvertible(self)
	}
}

extension Bool: JSONConvertible {
	public func jsonEncodedString() throws -> String {
		if true == self {
			return "true"
		}
		return "false"
	}
}

// !FIX! Downcasting to protocol does not work on Linux
// Not sure if this is intentional, or a bug.
func jsonEncodedStringWorkAround(o: Any) throws -> String {
	switch o {
	case let jsonAble as JSONConvertibleObject: // as part of Linux work around
		return try jsonAble.jsonEncodedString()
	case let jsonAble as JSONConvertible:
		return try jsonAble.jsonEncodedString()
	case let jsonAble as String:
		return try jsonAble.jsonEncodedString()
	case let jsonAble as Int:
		return try jsonAble.jsonEncodedString()
	case let jsonAble as UInt:
		return try jsonAble.jsonEncodedString()
	case let jsonAble as Double:
		return try jsonAble.jsonEncodedString()
	case let jsonAble as Bool:
		return try jsonAble.jsonEncodedString()
	case let jsonAble as [Any]:
		return try jsonAble.jsonEncodedString()
	case let jsonAble as [String:Any]:
		return try jsonAble.jsonEncodedString()
	default:
		throw JSONConversionError.NotConvertible(o)
	}
}

extension Array: JSONConvertible {
	public func jsonEncodedString() throws -> String {
		var s = "["
		var first = true
		for v in self {
			if !first {
				s.appendContentsOf(",")
			} else {
				first = false
			}
			s.appendContentsOf(try jsonEncodedStringWorkAround(v))
		}
		s.appendContentsOf("]")
		return s
	}
}

extension Dictionary: JSONConvertible {
	public func jsonEncodedString() throws -> String {
		var s = "{"
		
		var first = true
		
		for (k, v) in self {
			guard let strKey = k as? String else {
				throw JSONConversionError.InvalidKey(k)
			}
			if !first {
				s.appendContentsOf(",")
			} else {
				first = false
			}
			s.appendContentsOf(try strKey.jsonEncodedString())
			s.appendContentsOf(":")
			s.appendContentsOf(try jsonEncodedStringWorkAround(v))
		}
		
		s.appendContentsOf("}")
		return s

	}
}

/// Decode the JSON object represented by the String.
extension String {
	public func jsonDecode() throws -> JSONConvertible {
		
		let state = JSONDecodeState()
		state.g = self.unicodeScalars.generate()
		
		let o = try state.readObject()
		if let _ = o as? JSONDecodeState.EOF {
			throw JSONConversionError.SyntaxError
		}
		return o
	}
}

private class JSONDecodeState {
	
	struct EOF: JSONConvertible {
		func jsonEncodedString() throws -> String { return "" }
	}
	
	var g = String().unicodeScalars.generate()
	var pushBack: UnicodeScalar?
	
	func movePastWhite() {
		while let c = self.next() {
			if !c.isWhiteSpace() {
				self.pushBack = c
				break
			}
		}
	}
	
	func readObject() throws -> JSONConvertible {
		
		self.movePastWhite()
		
		guard let c = self.next() else {
			return EOF()
		}
		
		switch(c) {
		case jsonOpenArray:
			var a = [Any]()
			self.movePastWhite()
			guard let c = self.next() else {
				throw JSONConversionError.SyntaxError
			}
			if c != jsonCloseArray {
				self.pushBack = c
				while true {
					a.append(try readObject())
					self.movePastWhite()
					guard let c = self.next() else {
						throw JSONConversionError.SyntaxError
					}
					if c == jsonCloseArray {
						break
					}
					if c != jsonComma {
						throw JSONConversionError.SyntaxError
					}
				}
			}
			return a
		case jsonOpenObject:
			var d = [String:Any]()
			self.movePastWhite()
			guard let c = self.next() else {
				throw JSONConversionError.SyntaxError
			}
			if c != jsonCloseObject {
				self.pushBack = c
				while true {
					guard let key = try readObject() as? String else {
						throw JSONConversionError.SyntaxError
					}
					self.movePastWhite()
					guard let c = self.next() else {
						throw JSONConversionError.SyntaxError
					}
					guard c == jsonColon else {
						throw JSONConversionError.SyntaxError
					}
					self.movePastWhite()
					d[key] = try readObject()
					do {
						self.movePastWhite()
						guard let c = self.next() else {
							throw JSONConversionError.SyntaxError
						}
						if c == jsonCloseObject {
							break
						}
						if c != jsonComma {
							throw JSONConversionError.SyntaxError
						}
					}
				}
			}
			if let objid = d[JSONDecoding.objectIdentifierKey] as? String {
				if let o = JSONDecoding.createJSONConvertibleObject(objid, values: d) {
					return o
				}
			}
			return d
		case jsonQuoteDouble:
			return try readString()
		default:
			if c.isWhiteSpace() {
				// nothing
			} else if c.isDigit() || c == "-" || c == "+" {
				return try readNumber(c)
			} else if c == "t" || c == "T" {
				return try readTrue()
			} else if c == "f" || c == "F" {
				return try readFalse()
			} else if c == "n" || c == "N" {
				try readNull()
				return JSONConvertibleNull()
			}
		}
		throw JSONConversionError.SyntaxError
	}
	
	func next() -> UnicodeScalar? {
		if pushBack != nil {
			let c = pushBack!
			pushBack = nil
			return c
		}
		return g.next()
	}
	
	// the opening quote has been read
	func readString() throws -> String {
		var next = self.next()
		var esc = false
		var s = ""
		while let c = next {
			
			if esc {
				switch(c) {
				case jsonBackSlash:
					s.append(jsonBackSlash)
				case jsonQuoteDouble:
					s.append(jsonQuoteDouble)
				case "b":
					s.append(jsonBackSpace)
				case "f":
					s.append(jsonFormFeed)
				case "n":
					s.append(jsonLF)
				case "r":
					s.append(jsonCR)
				case "t":
					s.append(jsonTab)
				case "u":
					var hexStr = ""
					for _ in 1...4 {
						next = self.next()
						guard let hexC = next else {
							throw JSONConversionError.SyntaxError
						}
						guard hexC.isHexDigit() else {
							throw JSONConversionError.SyntaxError
						}
						hexStr.append(hexC)
					}
					let result = UnicodeScalar(UInt32(strtoul(hexStr, nil, 16)))
					s.append(result)
				default:
					s.append(c)
				}
				esc = false
			} else if c == jsonBackSlash {
				esc = true
			} else if c == jsonQuoteDouble {
				return s
			} else {
				s.append(c)
			}
			
			next = self.next()
		}
		throw JSONConversionError.SyntaxError
	}
	
	func readNumber(firstChar: UnicodeScalar) throws -> JSONConvertible {
		var s = ""
		var needPeriod = true, needExp = true
		s.append(firstChar)
		
		if firstChar == "." {
			needPeriod = false
		}
		
		var next = self.next()
		var last = firstChar
		while let c = next {
			if c.isDigit() {
				s.append(c)
			} else if c == "." && !needPeriod {
				break
			} else if (c == "e" || c == "E") && !needExp {
				break
			} else if c == "." {
				needPeriod = false
				s.append(c)
			} else if c == "e" || c == "E" {
				needExp = false
				s.append(c)
				
				next = self.next()
				if next != nil && (next! == "-" || next! == "+") {
					s.append(next!)
				} else {
					pushBack = next!
				}
				
			} else if last.isDigit() {
				pushBack = c
				if needPeriod && needExp {
					return Int(s)!
				}
				return Double(s)!
			} else {
				break
			}
			last = c
			next = self.next()
		}
		
		throw JSONConversionError.SyntaxError
	}
	
	func readTrue() throws -> Bool {
		var next = self.next()
		if next != "r" && next != "R" {
			throw JSONConversionError.SyntaxError
		}
		next = self.next()
		if next != "u" && next != "U" {
			throw JSONConversionError.SyntaxError
		}
		next = self.next()
		if next != "e" && next != "E" {
			throw JSONConversionError.SyntaxError
		}
		next = self.next()
		guard next != nil && !next!.isAlphaNum() else {
			throw JSONConversionError.SyntaxError
		}
		pushBack = next!
		return true
	}
	
	func readFalse() throws -> Bool {
		var next = self.next()
		if next != "a" && next != "A" {
			throw JSONConversionError.SyntaxError
		}
		next = self.next()
		if next != "l" && next != "L" {
			throw JSONConversionError.SyntaxError
		}
		next = self.next()
		if next != "s" && next != "S" {
			throw JSONConversionError.SyntaxError
		}
		next = self.next()
		if next != "e" && next != "E" {
			throw JSONConversionError.SyntaxError
		}
		next = self.next()
		guard next != nil && !next!.isAlphaNum() else {
			throw JSONConversionError.SyntaxError
		}
		pushBack = next!
		return false
	}
	
	func readNull() throws {
		var next = self.next()
		if next != "u" && next != "U" {
			throw JSONConversionError.SyntaxError
		}
		next = self.next()
		if next != "l" && next != "L" {
			throw JSONConversionError.SyntaxError
		}
		next = self.next()
		if next != "l" && next != "L" {
			throw JSONConversionError.SyntaxError
		}
		next = self.next()
		guard next != nil && !next!.isAlphaNum() else {
			throw JSONConversionError.SyntaxError
		}
		pushBack = next!
	}
}



















