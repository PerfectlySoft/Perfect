//
//  Utilities.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/17/15.
//	Copyright (C) 2015 PerfectlySoft, Inc.
//
//     This program is free software: you can redistribute it and/or modify
//     it under the terms of the GNU Affero General Public License as published by
//     the Free Software Foundation, either version 3 of the License, or
//     (at your option) any later version.
//
//     This program is distributed in the hope that it will be useful,
//     but WITHOUT ANY WARRANTY; without even the implied warranty of
//     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//     GNU Affero General Public License for more details.
//
//     You should have received a copy of the GNU Affero General Public License
//     along with this program.  If not, see <http://www.gnu.org/licenses/>.
//


/*
read/write lock cache code
This can easily be done using a custom concurrent queue and barriers. First, we'll create the dictionary and the queue:

_cache = [[NSMutableDictionary alloc] init];
_queue = dispatch_queue_create("com.mikeash.cachequeue", DISPATCH_QUEUE_CONCURRENT);
To read from the cache, we can just use a dispatch_sync:

- (id)cacheObjectForKey: (id)key
{
__block obj;
dispatch_sync(_queue, ^{
obj = [[_cache objectForKey: key] retain];
});
return [obj autorelease];
}
Because the queue is concurrent, this allows for concurrent access to the cache, and therefore no contention between multiple threads in the common case.

To write to the cache, we need a barrier:

- (void)setCacheObject: (id)obj forKey: (id)key
{
dispatch_barrier_async(_queue, ^{
[_cache setObject: obj forKey: key];
});
}

*/

import Foundation

internal func split_thread(closure:()->()) {
	dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), closure)
}

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
	public static func encode<D : UnicodeCodecType, G : GeneratorType where G.Element == D.CodeUnit>(var decoder : D, var generator: G) -> String {
		var encodedString = ""
		var finished: Bool = false
		repeat {
			let decodingResult = decoder.decode(&generator)
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
		return self.stringByAddingPercentEncodingWithAllowedCharacters(NSCharacterSet.URLQueryAllowedCharacterSet())!
	}
}

extension String {
	/// Parse uuid string
	/// Results are undefined if the string is not a valid UUID
	public func asUUID() -> uuid_t {
		let u = UnsafeMutablePointer<UInt8>.alloc(sizeof(uuid_t))
		defer {
			u.destroy() ; u.dealloc(sizeof(uuid_t))
		}
		uuid_parse(self, u)
		return uuid_t(u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7], u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15])
	}
	
	/// Unparse a uuid_t into the String representation.
	public static func fromUUID(uuid: uuid_t) -> String {
		let u = UnsafeMutablePointer<UInt8>.alloc(sizeof(uuid_t))
		let unu = UnsafeMutablePointer<Int8>.alloc(37) // as per spec. 36 + null
		
		defer {
			u.destroy() ; u.dealloc(sizeof(uuid_t))
			unu.destroy() ; unu.dealloc(37)
		}
		u[0] = uuid.0;u[1] = uuid.1;u[2] = uuid.2;u[3] = uuid.3;u[4] = uuid.4;u[5] = uuid.5;u[6] = uuid.6;u[7] = uuid.7
		u[8] = uuid.8;u[9] = uuid.9;u[10] = uuid.10;u[11] = uuid.11;u[12] = uuid.12;u[13] = uuid.13;u[14] = uuid.14;u[15] = uuid.15
		uuid_unparse_lower(u, unu)
		
		return String.fromCString(unu)!
	}
	
	/// Parse an HTTP Digest authentication header returning a Dictionary containing each part.
	public func parseAuthentication() -> [String:String] {
		var ret = [String:String]()
		if let _ = self.rangeOfString("Digest ") {
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
		guard let range = from.rangeOfString(named + "=") else {
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

/// Returns a blank uuid_t
public func empty_uuid() -> uuid_t {
	return uuid_t(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
}

/// Generate a random uuid_t
public func random_uuid() -> uuid_t {
	let u = UnsafeMutablePointer<UInt8>.alloc(sizeof(uuid_t))
	defer {
		u.destroy() ; u.dealloc(sizeof(uuid_t))
	}
	uuid_generate_random(u)
	// is there a better way?
	return uuid_t(u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7], u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15])
}

extension String {
	
	var lastPathComponent: String {
		
		get {
			return (self as NSString).lastPathComponent
		}
	}
	var pathExtension: String {
		
		get {
			
			return (self as NSString).pathExtension
		}
	}
	var stringByDeletingLastPathComponent: String {
		
		get {
			
			return (self as NSString).stringByDeletingLastPathComponent
		}
	}
	var stringByDeletingPathExtension: String {
		
		get {
			
			return (self as NSString).stringByDeletingPathExtension
		}
	}
	var pathComponents: [String] {
		
		get {
			
			return (self as NSString).pathComponents
		}
	}
	
	func stringByAppendingPathComponent(path: String) -> String {
		
		let nsSt = self as NSString
		
		return nsSt.stringByAppendingPathComponent(path)
	}
	
	func stringByAppendingPathExtension(ext: String) -> String? {
		
		let nsSt = self as NSString
		
		return nsSt.stringByAppendingPathExtension(ext)
	}
	
	var stringByResolvingSymlinksInPath: String {
		get {
			
			return (self as NSString).stringByResolvingSymlinksInPath
		}
	}
}
















