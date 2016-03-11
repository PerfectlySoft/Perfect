//
//  JSON.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/14/15.
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

private let jsonOpenObject = UnicodeScalar(UInt32(123))
private let jsonOpenArray = UnicodeScalar(UInt32(91))
private let jsonCloseObject = UnicodeScalar(UInt32(125))
private let jsonCloseArray = UnicodeScalar(UInt32(93))
private let jsonQuoteDouble = UnicodeScalar(UInt32(34))
private let jsonWhiteSpace = UnicodeScalar(UInt32(32))
private let jsonColon = UnicodeScalar(UInt32(58))
private let jsonComma = UnicodeScalar(UInt32(44))
private let jsonBackSlash = UnicodeScalar(UInt32(92))

private let jsonBackSpace = UnicodeScalar(UInt32(8))
private let jsonFormFeed = UnicodeScalar(UInt32(12))

private let jsonLF = UnicodeScalar(UInt32(10))
private let jsonCR = UnicodeScalar(UInt32(13))
private let jsonTab = UnicodeScalar(UInt32(9))

public typealias JSONKey = String
public typealias JSONValue = Any

/// An exception enum type which represents JSON encoding and decoding errors
public enum JSONError: ErrorType {
	/// A data type was used which is not JSON encodable.
	case UnhandledType(String)
	/// The JSON data was malformed.
	case SyntaxError(String)
}

class KeyPair {
	let key: JSONKey
	var value: JSONValue?
	
	init(key: JSONKey) {
		self.key = key
	}
}

/// This class encodes Arrays and Dictionaries into JSON text strings
///
/// Top-level values which may be encoded include
/// - `Array<JSONValue>`
/// - `Dictionary<String, JSONValue>`
/// - `JSONArray`
/// - `JSONDictionary`
///
/// A value in any of the container types may consist of
/// - `Int`
/// - `Double`
/// - `String`
/// - `Bool`
/// - `JSONNull`
/// - `JSONArray`
/// - `JSONDictionary`
/// - `Array<JSONValue>`
/// - `Dictionary<String, JSONValue>`
public class JSONEncoder {
	
	/// Empty public initializer
	public init() {
		
	}
	
	/// Encode a `JSONArrayType` into a JSON string
	/// - throws: A `JSONError.UnhandledType` exception
	public func encode(a: JSONArrayType) throws -> String {
		return try encode(a.array)
	}
	
	/// Encode an Array of objects into a JSON string
	/// - throws: A `JSONError.UnhandledType` exception
	public func encode(a: [JSONValue]) throws -> String {
		var s = "["
		var c = false
		for value in a {
			if c {
				s.appendContentsOf(",")
			} else {
				c = true
			}
			s.appendContentsOf(try encodeValue(value))
		}
		s.appendContentsOf("]")
		return s
	}
	
	/// Encode a `JSONDictionaryType` into a JSON string
	/// - throws: A `JSONError.UnhandledType` exception
	public func encode(a: JSONDictionaryType) throws -> String {
		return try encode(a.dictionary)
	}
	
	/// Encode a Dictionary into a JSON string
	/// - throws: A `JSONError.UnhandledType` exception
	public func encode(d: [String:JSONValue]) throws -> String {
		var s = "{"
		var c = false
		for (key, value) in d {
			if c {
				s.appendContentsOf(",")
			} else {
				c = true
			}
			s.appendContentsOf(encodeString(key))
			s.appendContentsOf(":")
			s.appendContentsOf(try encodeValue(value))
		}
		s.appendContentsOf("}")
		return s
	}
	
    /// Encode a `JSONValue` into a JSON string
    /// - throws: A `JSONError.UnhandledType` exception
	func encodeValue(value: JSONValue) throws -> String {
		
		switch(value) {
		case let b as Bool:
			return b ? "true" : "false"
		case let i as Int:
			return encodeInt(i)
		case let d as Double:
			return encodeDouble(d)
		case let s as String:
			return encodeString(s)
		case let ja as JSONArrayType:
			return try encodeArray(ja.array)
		case let a as Array<JSONValue>:
			return try encodeArray(a)
		case let jd as JSONDictionaryType:
			return try encodeDictionary(jd.dictionary)
		case let d as Dictionary<String, JSONValue>:
			return try encodeDictionary(d)
		case _ as JSONNull:
			return "null"
		default:
			throw JSONError.UnhandledType("The type \(value.dynamicType) was not handled")
		}
	}
	
    /// Encode a `String` into a JSON string
	func encodeString(src: String) -> String {
		var s = "\""
		for uchar in src.unicodeScalars {
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
	
    /// Encode an `Int` into a JSON string
 	func encodeInt(i: Int) -> String {
		return String(i)
	}
    
	/// Encode a `Double` into a JSON string
	func encodeDouble(d: Double) -> String {
		return String(d)
	}
	
    /// Encode an `Array` into a JSON string
    /// - throws: A `JSONError.UnhandledType` exception
	func encodeArray(a: Array<JSONValue>) throws -> String {
		return try encode(a)
	}
	
    /// Encode a `Dictionary<String, JSONValue>` intot a JSON string
    /// - throws: A `JSONError.UnhandledType` exception
	func encodeDictionary(d: Dictionary<String, JSONValue>) throws -> String {
		return try encode(d)
	}
	
}

/// This class is used to represent a JSON null
/// An instance of this class can be used in an Array of Dictionary which is to be encoded.
/// An instance of this class may be found in any decoded Array or Dictionary.
public class JSONNull {
	/// Empty public initializer
	public init() {
		
	}
}

/// This class is a reference based wrapper around `Array<JSONValue>`
/// JSON data which is being decoded will have these object as part of the contents of the resulting data.
public class JSONArrayType {
	
	/// Provides access to the underlying array
	public var array = Array<JSONValue>()
	
	public subscript (index: Int) -> Array<JSONValue>.Element {
		return array[index]
	}
	
	/// Pass-through function which appends to the array.
	public func append(a: JSONValue) {
		array.append(a)
	}
}

/// This class is a referenced based wrapper around `Dictionary<String, JSONValue>`
/// JSON data which is being decoded will have these object as part of the contents of the resulting data.
public class JSONDictionaryType {
	
	public typealias DictionaryType = Dictionary<JSONKey, JSONValue>
	public typealias Key = DictionaryType.Key
	public typealias Value = DictionaryType.Value
	
	/// Provides access to the underlying Dictionary.
	public var dictionary = DictionaryType()
	
	public subscript (key: Key) -> Value? {
		get {
			return dictionary[key]
		}
		set(newValue) {
			dictionary[key] = newValue
		}
	}
}

private let malformedJSONString = "Malformed JSON string"

/// This class decodes JSON string data and returns the resulting value(s)
///
/// A resulting value may consist of
/// - `Int`
/// - `Double`
/// - `String`
/// - `Bool`
/// - `JSONNull`
/// - `JSONArray`
/// - `JSONDictionary`
public class JSONDecoder {
	
	var stack = Array<JSONValue>()
	var exit: JSONValue?
	
	var g = String().unicodeScalars.generate()
	var pushBack: UnicodeScalar?
	
	/// Empty public initializer
	public init() {
		
	}
	
	/// Decode a JSON string and return the result
	/// - parameter s: The JSON string data
	/// - throws: `JSONError.SyntaxError`
	/// - returns: The resulting object which may be one of `Int`, `Double`, `String`, `Bool`, `JSONNull`, `JSONArray` or `JSONDictionary`
	public func decode(s: String) throws -> JSONValue {
		
		let scalars = s.unicodeScalars
		g = scalars.generate()
		
		try readObjects()
		
		guard stack.count == 0 && exit != nil else {
			throw JSONError.SyntaxError("Unterminated JSON string")
		}
		
		return exit!
	}
	
	func readObjects() throws {
		
		var next = self.next()
		
		while let c = next {
			
			switch(c) {
			case jsonOpenArray:
				stack.append(JSONArrayType())
			case jsonOpenObject:
				stack.append(JSONDictionaryType())
			case jsonCloseArray:
				try handlePop()
			case jsonCloseObject:
				try handlePop()
			case jsonColon:
				guard stack.count > 0 && stack.last! is KeyPair && (stack.last! as! KeyPair).value == nil else {
					throw JSONError.SyntaxError(malformedJSONString)
				}
			case jsonComma:
				guard stack.count > 0 && !(stack.last! is KeyPair) else {
					throw JSONError.SyntaxError(malformedJSONString)
				}
			case jsonQuoteDouble:
				try handlePop(try readString())
			default:
				if c.isWhiteSpace() {
					// nothing
				} else if c.isDigit() || c == "-" || c == "+" {
					try handlePop(try readNumber(c))
				} else if c == "t" || c == "T" {
					try handlePop(try readTrue())
				} else if c == "f" || c == "F" {
					try handlePop(try readFalse())
				} else if c == "n" || c == "N" {
					try handlePop(try readNull())
				}
			}
			next = self.next()
		}
	}
	
	func pop() throws -> JSONValue {
		guard stack.count > 0 else {
			throw JSONError.SyntaxError(malformedJSONString)
		}
		return stack.removeLast()
	}
	
	func handleNested(top: JSONValue, obj: JSONValue) throws -> JSONValue {
		// top must be array or dictionary or KeyPair with value of nil
		// if top is dictionary, obj must be KeyPair
		
		switch top {
		case let a as JSONArrayType:
			a.append(obj)
			return a // ?
		case let d as JSONDictionaryType:
			switch obj {
			case let keyPair as KeyPair:
				guard keyPair.value != nil else {
					throw JSONError.SyntaxError(malformedJSONString)
				}
				d[keyPair.key] = keyPair.value!
				return d
			case let s as String:
				let ky = KeyPair(key: s)
				stack.append(ky)
				return ky
			default:
				throw JSONError.SyntaxError(malformedJSONString)
			}
		case let pair as KeyPair:
			guard pair.value == nil else {
				throw JSONError.SyntaxError(malformedJSONString)
			}
			pair.value = obj
			try pop()
			return try handlePop(pair)
		default:
			throw JSONError.SyntaxError(malformedJSONString)
		}
	}
	
	func handlePop(a: JSONValue) throws -> JSONValue {
		if stack.count > 0 {
			return try handleNested(stack.last!, obj: a)
		}
		exit = a // done
		return a
	}
	
	func handlePop() throws -> JSONValue {
		
		guard stack.count > 0 else {
			throw JSONError.SyntaxError(malformedJSONString)
		}
		
		return try handlePop(try pop())
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
							throw JSONError.SyntaxError("Malformed hex sequence")
						}
						guard hexC.isHexDigit() else {
							throw JSONError.SyntaxError("Malformed hex sequence")
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
		throw JSONError.SyntaxError("Unterminated string literal")
	}
	
	func readNumber(firstChar: UnicodeScalar) throws -> JSONValue {
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
		
		throw JSONError.SyntaxError("Malformed numeric literal")
	}
	
	func readTrue() throws -> Bool {
		var next = self.next()
		if next != "r" && next != "R" {
			throw JSONError.SyntaxError("Malformed boolean literal")
		}
		next = self.next()
		if next != "u" && next != "U" {
			throw JSONError.SyntaxError("Malformed boolean literal")
		}
		next = self.next()
		if next != "e" && next != "E" {
			throw JSONError.SyntaxError("Malformed boolean literal")
		}
		next = self.next()
		guard next != nil && !next!.isAlphaNum() else {
			throw JSONError.SyntaxError("Malformed boolean literal")
		}
		pushBack = next!
		return true
	}
	
	func readFalse() throws -> Bool {
		var next = self.next()
		if next != "a" && next != "A" {
			throw JSONError.SyntaxError("Malformed boolean literal")
		}
		next = self.next()
		if next != "l" && next != "L" {
			throw JSONError.SyntaxError("Malformed boolean literal")
		}
		next = self.next()
		if next != "s" && next != "S" {
			throw JSONError.SyntaxError("Malformed boolean literal")
		}
		next = self.next()
		if next != "e" && next != "E" {
			throw JSONError.SyntaxError("Malformed boolean literal")
		}
		next = self.next()
		guard next != nil && !next!.isAlphaNum() else {
			throw JSONError.SyntaxError("Malformed boolean literal")
		}
		pushBack = next!
		return false
	}
	
	func readNull() throws -> JSONNull {
		var next = self.next()
		if next != "u" && next != "U" {
			throw JSONError.SyntaxError("Malformed null literal")
		}
		next = self.next()
		if next != "l" && next != "L" {
			throw JSONError.SyntaxError("Malformed null literal")
		}
		next = self.next()
		if next != "l" && next != "L" {
			throw JSONError.SyntaxError("Malformed null literal")
		}
		next = self.next()
		guard next != nil && !next!.isAlphaNum() else {
			throw JSONError.SyntaxError("Malformed null literal")
		}
		pushBack = next!
		return JSONNull()
	}
	
	func next() -> UnicodeScalar? {
		if pushBack != nil {
			let c = pushBack!
			pushBack = nil
			return c
		}
		return g.next()
	}
}









