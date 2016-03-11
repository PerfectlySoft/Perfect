//
//  BSON.swift
//  BSON
//
//  Created by Kyle Jessup on 2015-11-18.
//  Copyright © 2015 PerfectlySoft. All rights reserved.
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

import libmongoc

public enum BSONError: ErrorType {
	/// The JSON data was malformed.
	case SyntaxError(String)
}

public class BSON: CustomStringConvertible {
	var doc: UnsafeMutablePointer<bson_t>

	public var description: String {
		return self.asString
	}

	public init() {
		self.doc = bson_new()
	}

	public init(bytes: [UInt8]) {
		self.doc = bson_new_from_data(bytes, bytes.count)
	}

	public init(json: String) throws {
		var error = bson_error_t()
		self.doc = bson_new_from_json(json, json.utf8.count, &error)
		if self.doc == nil {
			let message = withUnsafePointer(&error.message) {
				String.fromCString(UnsafePointer($0))!
			}
			throw BSONError.SyntaxError(message)
		}
	}

	public init(document: BSON) {
		self.doc = bson_copy(document.doc)
	}

	init(rawBson: UnsafeMutablePointer<bson_t>) {
		self.doc = rawBson
	}
    
    deinit {
        close()
    }

	public func close() {
		if self.doc != nil {
			bson_destroy(self.doc)
			self.doc = nil
		}
	}

	public var asString: String {
		var length = 0
		let data = bson_as_json(self.doc, &length)
		defer {
			bson_free(data)
		}
		return String.fromCString(data)!
	}

	public var asArrayString: String {
		var length = 0
		let data = bson_array_as_json(self.doc, &length)
		defer {
			bson_free(data)
		}
		return String.fromCString(data)!
	}

	public var asBytes: [UInt8] {
		let length = Int(self.doc.memory.len)
		let data = bson_get_data(self.doc)
		var ret = [UInt8]()
		for i in 0..<length {
			ret.append(data[i])
		}
		return ret
	}

	public func append(key: String, document: BSON) -> Bool {
		return bson_append_document(self.doc, key, -1, document.doc)
	}

	public func append(key: String) -> Bool {
		return bson_append_null(self.doc, key, -1)
	}

	public func append(key: String, oid: bson_oid_t) -> Bool {
		var cpy = oid
		return bson_append_oid(self.doc, key, -1, &cpy)
	}

	public func append(key: String, int: Int) -> Bool {
		return bson_append_int64(self.doc, key, -1, Int64(int))
	}

	public func append(key: String, int32: Int32) -> Bool {
		return bson_append_int32(self.doc, key, -1, int32)
	}

	public func append(key: String, dateTime: Int64) -> Bool {
		return bson_append_date_time(self.doc, key, -1, dateTime)
	}

	public func append(key: String, time: time_t) -> Bool {
		return bson_append_time_t(self.doc, key, -1, time)
	}

	public func append(key: String, double: Double) -> Bool {
		return bson_append_double(self.doc, key, -1, double)
	}

	public func append(key: String, bool: Bool) -> Bool {
		return bson_append_bool(self.doc, key, -1, bool)
	}

	public func append(key: String, string: String) -> Bool {
		return bson_append_utf8(self.doc, key, -1, string, -1)
	}

	public func append(key: String, bytes: [UInt8]) -> Bool {
		return bson_append_binary(self.doc, key, -1, BSON_SUBTYPE_BINARY, bytes, UInt32(bytes.count))
	}

	public func append(key: String, regex: String, options: String) -> Bool {
		return bson_append_regex(self.doc, key, -1, regex, options)
	}

	public func countKeys() -> Int {
		return Int(bson_count_keys(self.doc))
	}

	public func hasField(key: String) -> Bool {
		return bson_has_field(self.doc, key)
	}

	public func appendArrayBegin(key: String, child: BSON) -> Bool {
		return bson_append_array_begin(self.doc, key, -1, child.doc)
	}

	public func appendArrayEnd(child: BSON) -> Bool {
		return bson_append_array_end(self.doc, child.doc)
	}

	public func appendArray(key: String, array: BSON) -> Bool {
		return bson_append_array(self.doc, key, -1, array.doc)
	}

	public func concat(src: BSON) -> Bool {
		return bson_concat(self.doc, src.doc)
	}
}

public func ==(lhs: BSON, rhs: BSON) -> Bool {
	let cmp = bson_compare(lhs.doc, rhs.doc)
	return cmp == 0
}

public func <(lhs: BSON, rhs: BSON) -> Bool {
	let cmp = bson_compare(lhs.doc, rhs.doc)
	return cmp < 0
}

extension BSON: Comparable {}

class NoDestroyBSON: BSON {

	override func close() {
		self.doc = nil
	}

}
