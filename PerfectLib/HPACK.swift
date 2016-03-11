//
//  HPACK.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2016-02-18.
//  Copyright © 2016 PerfectlySoft. All rights reserved.
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

// HPACK support for HTTP/2
// This code is modeled after Twitter's hpack library https://github.com/twitter/hpack
// Which is an implimentation of https://tools.ietf.org/html/rfc7541

class HeaderField {
	static let headerEntryOverhead = 32
	
	let name: [UInt8]
	let value: [UInt8]
	
	var size: Int {
		return name.count + value.count + HeaderField.headerEntryOverhead
	}
	
	var nameStr: String {
		return UTF8Encoding.encode(name)
	}
	
	init(name: [UInt8], value: [UInt8]) {
		self.name = name
		self.value = value
	}
	
	init(name: String, value: String) {
		self.name = UTF8Encoding.decode(name)
		self.value = UTF8Encoding.decode(value)
	}
	
	convenience init(name: String) {
		self.init(name: name, value: "")
	}
	
	static func sizeOf(name: [UInt8], value: [UInt8]) -> Int {
		return name.count + value.count + headerEntryOverhead
	}
}

class DynamicTable {
	
	var headerFields = [HeaderField?]()
	var head = 0
	var tail = 0
	var size = 0
	var capacity = -1 {
		didSet {
			self.capacityChanged(oldValue)
		}
	}
	
	var length: Int {
		if head < tail {
			return headerFields.count - tail + head
		}
		return head - tail
	}
	
	init(initialCapacity: Int) {
		self.capacity = initialCapacity
		self.capacityChanged(-1)
	}
	
	private func capacityChanged(oldValue: Int) {
		guard capacity >= 0 else {
			return
		}
		guard capacity != oldValue else {
			return
		}
		if capacity == 0 {
			clear()
		} else {
			while size > capacity {
				remove()
			}
		}
		
		var maxEntries = capacity / HeaderField.headerEntryOverhead
		if capacity % HeaderField.headerEntryOverhead != 0 {
			maxEntries += 1
		}
		
		if headerFields.count != maxEntries {
			var tmp = [HeaderField?](count: maxEntries, repeatedValue: nil)
			
			let len = length
			var cursor = tail
			
			for i in 0..<len {
				tmp[i] = headerFields[cursor]
				if cursor == headerFields.count {
					cursor = 0
				} else {
					cursor += 1
				}
			}
			
			tail = 0
			head = tail + len
			headerFields = tmp
		}
	}
	
	func clear() {
		while tail != head {
			headerFields[tail] = nil
			tail += 1
			if tail == headerFields.count {
				tail = 0
			}
		}
		head = 0
		tail = 0
		size = 0
	}
	
	func remove() -> HeaderField? {
		guard let removed = headerFields[tail] else {
			return nil
		}
		size -= removed.size
		headerFields[tail] = nil
		tail += 1
		if tail == headerFields.count {
			tail = 0
		}
		return removed
	}
	
	func getEntry(index: Int) -> HeaderField {
		let i = head - index
		if i < 0 {
			return headerFields[i + headerFields.count]!
		}
		return headerFields[i]!
	}
	
	func add(header: HeaderField) {
		let headerSize = header.size
		if headerSize > capacity {
			clear()
		} else {
			while size + headerSize > capacity {
				remove()
			}
			headerFields[head] = header
			head += 1
			size += header.size
			if head == headerFields.count {
				head = 0
			}
		}
	}
}

class StaticTable {
	
	static let table = [
		HeaderField(name: ":authority"),
		HeaderField(name: ":method", value: "GET"),
		HeaderField(name: ":method", value: "POST"),
		HeaderField(name: ":path", value: "/"),
		HeaderField(name: ":path", value: "/index.html"),
		HeaderField(name: ":scheme", value: "http"),
		HeaderField(name: ":scheme", value: "https"),
		HeaderField(name: ":status", value: "200"),
		HeaderField(name: ":status", value: "204"),
		HeaderField(name: ":status", value: "206"),
		HeaderField(name: ":status", value: "304"),
		HeaderField(name: ":status", value: "400"),
		HeaderField(name: ":status", value: "404"),
		HeaderField(name: ":status", value: "500"),
		HeaderField(name: "accept-charset"),
		HeaderField(name: "accept-encoding", value: "gzip, deflate"),
		HeaderField(name: "accept-language"),
		HeaderField(name: "accept-ranges"),
		HeaderField(name: "accept"),
		HeaderField(name: "access-control-allow-origin"),
		HeaderField(name: "age"),
		HeaderField(name: "allow"),
		HeaderField(name: "authorization"),
		HeaderField(name: "cache-control"),
		HeaderField(name: "content-disposition"),
		HeaderField(name: "content-encoding"),
		HeaderField(name: "content-language"),
		HeaderField(name: "content-length"),
		HeaderField(name: "content-location"),
		HeaderField(name: "content-range"),
		HeaderField(name: "content-type"),
		HeaderField(name: "cookie"),
		HeaderField(name: "date"),
		HeaderField(name: "etag"),
		HeaderField(name: "expect"),
		HeaderField(name: "expires"),
		HeaderField(name: "from"),
		HeaderField(name: "host"),
		HeaderField(name: "if-match"),
		HeaderField(name: "if-modified-since"),
		HeaderField(name: "if-none-match"),
		HeaderField(name: "if-range"),
		HeaderField(name: "if-unmodified-since"),
		HeaderField(name: "last-modified"),
		HeaderField(name: "link"),
		HeaderField(name: "location"),
		HeaderField(name: "max-forwards"),
		HeaderField(name: "proxy-authenticate"),
		HeaderField(name: "proxy-authorization"),
		HeaderField(name: "range"),
		HeaderField(name: "referer"),
		HeaderField(name: "refresh"),
		HeaderField(name: "retry-after"),
		HeaderField(name: "server"),
		HeaderField(name: "set-cookie"),
		HeaderField(name: "strict-transport-security"),
		HeaderField(name: "transfer-encoding"),
		HeaderField(name: "user-agent"),
		HeaderField(name: "vary"),
		HeaderField(name: "via"),
		HeaderField(name: "www-authenticate")
	]
	
	static let tableByName: [String:Int] = {
		var ret = [String:Int]()
		var i = table.count
		
		while i > 0 {
			ret[StaticTable.getEntry(i).nameStr] = i
			i -= 1
		}
		
		return ret
	}()
	
	static let length = table.count
	
	static func getEntry(index: Int) -> HeaderField {
		return table[index - 1]
	}
	
	static func getIndex(name: [UInt8]) -> Int {
		let s = UTF8Encoding.encode(name)
		if let idx = tableByName[s] {
			return idx
		}
		return -1
	}
	
	static func getIndex(name: [UInt8], value: [UInt8]) -> Int {
		let idx = getIndex(name)
		if idx != -1 {
			for i in idx...length {
				let entry = getEntry(i)
				if entry.name != name {
					break
				}
				if entry.value == value {
					return i
				}
			}
		}
		return -1
	}
}

func ==(lhs: [UInt8], rhs: [UInt8]) -> Bool {
	let c1 = lhs.count
	if c1 == rhs.count {
		for i in 0..<c1 {
			if lhs[i] != rhs[i] {
				return false
			}
		}
		return true
	}
	return false
}

/// This protocol is used to receive headers during HPACK decoding.
public protocol HeaderListener {
	/// A new header field and value has been decoded.
	func addHeader(name: [UInt8], value: [UInt8], sensitive: Bool)
}

enum IndexType {
	case Incremental, None, Never
}

private let huffmanCodes: [Int] = [
	0x1ff8,
	0x7fffd8,
	0xfffffe2,
	0xfffffe3,
	0xfffffe4,
	0xfffffe5,
	0xfffffe6,
	0xfffffe7,
	0xfffffe8,
	0xffffea,
	0x3ffffffc,
	0xfffffe9,
	0xfffffea,
	0x3ffffffd,
	0xfffffeb,
	0xfffffec,
	0xfffffed,
	0xfffffee,
	0xfffffef,
	0xffffff0,
	0xffffff1,
	0xffffff2,
	0x3ffffffe,
	0xffffff3,
	0xffffff4,
	0xffffff5,
	0xffffff6,
	0xffffff7,
	0xffffff8,
	0xffffff9,
	0xffffffa,
	0xffffffb,
	0x14,
	0x3f8,
	0x3f9,
	0xffa,
	0x1ff9,
	0x15,
	0xf8,
	0x7fa,
	0x3fa,
	0x3fb,
	0xf9,
	0x7fb,
	0xfa,
	0x16,
	0x17,
	0x18,
	0x0,
	0x1,
	0x2,
	0x19,
	0x1a,
	0x1b,
	0x1c,
	0x1d,
	0x1e,
	0x1f,
	0x5c,
	0xfb,
	0x7ffc,
	0x20,
	0xffb,
	0x3fc,
	0x1ffa,
	0x21,
	0x5d,
	0x5e,
	0x5f,
	0x60,
	0x61,
	0x62,
	0x63,
	0x64,
	0x65,
	0x66,
	0x67,
	0x68,
	0x69,
	0x6a,
	0x6b,
	0x6c,
	0x6d,
	0x6e,
	0x6f,
	0x70,
	0x71,
	0x72,
	0xfc,
	0x73,
	0xfd,
	0x1ffb,
	0x7fff0,
	0x1ffc,
	0x3ffc,
	0x22,
	0x7ffd,
	0x3,
	0x23,
	0x4,
	0x24,
	0x5,
	0x25,
	0x26,
	0x27,
	0x6,
	0x74,
	0x75,
	0x28,
	0x29,
	0x2a,
	0x7,
	0x2b,
	0x76,
	0x2c,
	0x8,
	0x9,
	0x2d,
	0x77,
	0x78,
	0x79,
	0x7a,
	0x7b,
	0x7ffe,
	0x7fc,
	0x3ffd,
	0x1ffd,
	0xffffffc,
	0xfffe6,
	0x3fffd2,
	0xfffe7,
	0xfffe8,
	0x3fffd3,
	0x3fffd4,
	0x3fffd5,
	0x7fffd9,
	0x3fffd6,
	0x7fffda,
	0x7fffdb,
	0x7fffdc,
	0x7fffdd,
	0x7fffde,
	0xffffeb,
	0x7fffdf,
	0xffffec,
	0xffffed,
	0x3fffd7,
	0x7fffe0,
	0xffffee,
	0x7fffe1,
	0x7fffe2,
	0x7fffe3,
	0x7fffe4,
	0x1fffdc,
	0x3fffd8,
	0x7fffe5,
	0x3fffd9,
	0x7fffe6,
	0x7fffe7,
	0xffffef,
	0x3fffda,
	0x1fffdd,
	0xfffe9,
	0x3fffdb,
	0x3fffdc,
	0x7fffe8,
	0x7fffe9,
	0x1fffde,
	0x7fffea,
	0x3fffdd,
	0x3fffde,
	0xfffff0,
	0x1fffdf,
	0x3fffdf,
	0x7fffeb,
	0x7fffec,
	0x1fffe0,
	0x1fffe1,
	0x3fffe0,
	0x1fffe2,
	0x7fffed,
	0x3fffe1,
	0x7fffee,
	0x7fffef,
	0xfffea,
	0x3fffe2,
	0x3fffe3,
	0x3fffe4,
	0x7ffff0,
	0x3fffe5,
	0x3fffe6,
	0x7ffff1,
	0x3ffffe0,
	0x3ffffe1,
	0xfffeb,
	0x7fff1,
	0x3fffe7,
	0x7ffff2,
	0x3fffe8,
	0x1ffffec,
	0x3ffffe2,
	0x3ffffe3,
	0x3ffffe4,
	0x7ffffde,
	0x7ffffdf,
	0x3ffffe5,
	0xfffff1,
	0x1ffffed,
	0x7fff2,
	0x1fffe3,
	0x3ffffe6,
	0x7ffffe0,
	0x7ffffe1,
	0x3ffffe7,
	0x7ffffe2,
	0xfffff2,
	0x1fffe4,
	0x1fffe5,
	0x3ffffe8,
	0x3ffffe9,
	0xffffffd,
	0x7ffffe3,
	0x7ffffe4,
	0x7ffffe5,
	0xfffec,
	0xfffff3,
	0xfffed,
	0x1fffe6,
	0x3fffe9,
	0x1fffe7,
	0x1fffe8,
	0x7ffff3,
	0x3fffea,
	0x3fffeb,
	0x1ffffee,
	0x1ffffef,
	0xfffff4,
	0xfffff5,
	0x3ffffea,
	0x7ffff4,
	0x3ffffeb,
	0x7ffffe6,
	0x3ffffec,
	0x3ffffed,
	0x7ffffe7,
	0x7ffffe8,
	0x7ffffe9,
	0x7ffffea,
	0x7ffffeb,
	0xffffffe,
	0x7ffffec,
	0x7ffffed,
	0x7ffffee,
	0x7ffffef,
	0x7fffff0,
	0x3ffffee,
	0x3fffffff // EOS
]

private let huffmanCodeLengths: [UInt8] = [
	13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
	28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
	6, 10, 10, 12, 13,  6,  8, 11, 10, 10,  8, 11,  8,  6,  6,  6,
	5,  5,  5,  6,  6,  6,  6,  6,  6,  6,  7,  8, 15,  6, 12, 10,
	13,  6,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,
	7,  7,  7,  7,  7,  7,  7,  7,  8,  7,  8, 13, 19, 13, 14,  6,
	15,  5,  6,  5,  6,  5,  6,  6,  6,  5,  7,  7,  6,  6,  6,  5,
	6,  7,  6,  5,  5,  6,  7,  7,  7,  7,  7, 15, 11, 14, 13, 28,
	20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
	24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
	22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
	21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
	26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
	19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
	20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
	26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
	30 // EOS
]

let huffmanEOS = 256

class HuffmanEncoder {
	
	let codes: [Int]
	let lengths: [UInt8]
	
	init(codes: [Int], lengths: [UInt8]) {
		self.codes = codes
		self.lengths = lengths
	}
	
	func encode(input: Bytes) throws -> Bytes {
		let o = Bytes()
		try encode(o, input: input)
		return o
	}
	
	func encode(out: Bytes, input: Bytes) throws {
		var current = 0
		var n = 0
		
		while input.availableExportBytes > 0 {
			let b = Int(input.export8Bits()) & 0xFF
			let code = codes[b]
			let nbits = Int(lengths[b])
			
			current <<= nbits
			current |= code
			n += nbits
			
			while n >= 8 {
				n -= 8
				let newVal = (current >> n) & 0xFF
				out.import8Bits(UInt8(newVal))
			}
		}
		if n > 0 {
			current <<= (8 - n)
			current |= (0xFF >> n)
			let newVal = current & 0xFF
			out.import8Bits(UInt8(newVal))
		}
	}
	
	func getEncodedLength(data: [UInt8]) -> Int {
		var len = 0
		for b in data {
			len += Int(lengths[Int(b & 0xFF)])
		}
		return (len + 7) >> 3
	}
}

class HuffmanDecoder {
	
	enum Exception: ErrorType {
		case EOSDecoded, InvalidPadding
	}
	
	class Node {
		let symbol: Int
		let bits: UInt8
		var children: [Node?]?
		
		var isTerminal: Bool {
			return self.children == nil
		}
		
		init() {
			self.symbol = 0
			self.bits = 8
			self.children = [Node?](count: 256, repeatedValue: nil)
		}
		
		init(symbol: Int, bits: UInt8) {
			self.symbol = symbol
			self.bits = bits
			self.children = nil
		}
	}
	
	let root: Node
	
	init(codes: [Int], lengths: [UInt8]) {
		self.root = HuffmanDecoder.buildTree(codes, lengths: lengths)
	}
	
	func decode(buf: [UInt8]) throws -> [UInt8] {
		var retBytes = [UInt8]()
		
		var node = root
		var current = 0
		var bits = 0
		for byte in buf {
			let b = byte & 0xFF
			current = (current << 8) | Int(b)
			bits += 8
			while bits >= 8 {
				let c = (current >> (bits - 8)) & 0xFF
				node = node.children![c]!
				bits -= Int(node.bits)
				if node.isTerminal {
					if node.symbol == huffmanEOS {
						throw Exception.EOSDecoded
					}
					retBytes.append(UInt8(node.symbol))
					node = root
				}
			}
		}
		
		while bits > 0 {
			let c = (current << (8 - bits)) & 0xFF
			node = node.children![c]!
			if node.isTerminal && Int(node.bits) <= bits {
				bits -= Int(node.bits)
				retBytes.append(UInt8(node.symbol))
				node = root
			} else {
				break
			}
		}
		
		let mask = (1 << bits) - 1
		if (current & mask) != mask {
			throw Exception.InvalidPadding
		}
		
		return retBytes
	}
	
	static func buildTree(codes: [Int], lengths: [UInt8]) -> Node {
		let root = Node()
		for i in 0..<codes.count {
			insert(root, symbol: i, code: codes[i], length: lengths[i])
		}
		return root
	}
	
	static func insert(root: Node, symbol: Int, code: Int, length: UInt8) {
		var current = root
		var len = Int(length)
		while len > 8 {
			len -= 8
			let i = (code >> len) & 0xFF
			if nil == current.children![i] {
				current.children![i] = Node()
			}
			current = current.children![i]!
		}
		let terminal = Node(symbol: symbol, bits: length)
		let shift = 8 - len
		let start = (code << shift) & 0xFF
		let end = 1 << shift
		for i in start..<(start+end) {
			current.children![i] = terminal
		}
	}
}

let huffmanEncoderInstance = HuffmanEncoder(codes: huffmanCodes, lengths: huffmanCodeLengths)
let huffmanDecoderInstance = HuffmanDecoder(codes: huffmanCodes, lengths: huffmanCodeLengths)

/// Encodes headers according to the HPACK standard.
public class HPACKEncoder {
	
	static let bucketSize = 17
	static let empty = [UInt8]()
	static let INDEX_MAX = 2147483647
	static let INDEX_MIN = -2147483648
	
	var headerFields: [HeaderEntry?]
	var head = HeaderEntry(hash: -1, name: empty, value: empty, index: INDEX_MAX, next: nil)
	var size = 0
	var capacity = 0
	
	var maxHeaderTableSize: Int { return capacity }
	var length: Int {
		return size == 0 ? 0 : head.after!.index - head.before!.index + 1
	}
	
	class HeaderEntry: HeaderField {
		
		var before: HeaderEntry?
		var after: HeaderEntry?
		var next: HeaderEntry?
		
		let hash: Int
		let index: Int
		
		init(hash: Int, name: [UInt8], value: [UInt8], index: Int, next: HeaderEntry?) {
			self.index = index
			self.hash = hash
			super.init(name: name, value: value)
			self.next = next
		}
		
		func remove() {
			before!.after = after
			after!.before = before
		}
		
		func addBefore(existingEntry: HeaderEntry) {
			after = existingEntry
			before = existingEntry.before
			before!.after = self
			after!.before = self
		}
	}
	
	/// Construct an HPACKEncoder with the indicated maximum capacity.
	public init(maxCapacity: Int = 256) {
		self.capacity = maxCapacity
		self.head.after = self.head
		self.head.before = self.head
		self.headerFields = [HeaderEntry?](count: HPACKEncoder.bucketSize, repeatedValue: nil)
	}
	
	/// Encodes a new header field and value, writing the results to out Bytes.
	public func encodeHeader(out: Bytes, name: String, value: String, sensitive: Bool = false, incrementalIndexing: Bool = true) throws {
		return try encodeHeader(out, name: UTF8Encoding.decode(name), value: UTF8Encoding.decode(value), sensitive: sensitive, incrementalIndexing: incrementalIndexing)
	}
	
	/// Encodes a new header field and value, writing the results to out Bytes.
	public func encodeHeader(out: Bytes, name: [UInt8], value: [UInt8], sensitive: Bool = false, incrementalIndexing: Bool = true) throws {
		if sensitive {
			let nameIndex = getNameIndex(name)
			try encodeLiteral(out, name: name, value: value, indexType: .Never, nameIndex: nameIndex)
			return
		}
		if capacity == 0 {
			let staticTableIndex = StaticTable.getIndex(name, value: value)
			if staticTableIndex == -1 {
				let nameIndex = StaticTable.getIndex(name)
				try encodeLiteral(out, name: name, value: value, indexType: .None, nameIndex: nameIndex)
			} else {
				encodeInteger(out, mask: 0x80, n: 7, i: staticTableIndex)
			}
			return
		}
		let headerSize = HeaderField.sizeOf(name, value: value)
		if headerSize > capacity {
			let nameIndex = getNameIndex(name)
			try encodeLiteral(out, name: name, value: value, indexType: .None, nameIndex: nameIndex)
		} else if let headerField = getEntry(name, value: value) {
			let index = getIndex(headerField.index) + StaticTable.length
			encodeInteger(out, mask: 0x80, n: 7, i: index)
		} else {
			let staticTableIndex = StaticTable.getIndex(name, value: value)
			if staticTableIndex != -1 {
				encodeInteger(out, mask: 0x80, n: 7, i: staticTableIndex)
			} else {
				let nameIndex = getNameIndex(name)
				ensureCapacity(headerSize)
				let indexType = incrementalIndexing ? IndexType.Incremental : IndexType.None
				try encodeLiteral(out, name: name, value: value, indexType: indexType, nameIndex: nameIndex)
				add(name, value: value)
			}
		}
	}
	
	func index(h: Int) -> Int {
		return h % HPACKEncoder.bucketSize
	}
	
	func hash(name: [UInt8]) -> Int {
		var h = 0
		for b in name {
			h = 31 &* h &+ Int(b)
		}
		if h > 0 {
			return h
		}
		if h == HPACKEncoder.INDEX_MIN {
			return HPACKEncoder.INDEX_MAX
		}
		return -h
	}
	
	func clear() {
		for i in 0..<self.headerFields.count {
			self.headerFields[i] = nil
		}
		head.before = head
		head.after = head
		size = 0
	}
	
	func remove() -> HeaderField? {
		if size == 0 {
			return nil
		}
		let eldest = head.after
		let h = eldest!.hash
		let i = index(h)
		
		var prev = headerFields[i]
		var e = prev
		
		while let ee = e {
			let next = ee.next
			if ee === eldest! {
				if prev === eldest! {
					headerFields[i] = next
				} else {
					prev!.next = next
				}
				eldest!.remove()
				size -= eldest!.size
				return eldest
			}
			prev = e
			e = next
		}
		return nil
	}
	
	func add(name: [UInt8], value: [UInt8]) {
		let headerSize = HeaderField.sizeOf(name, value: value)
		
		if headerSize > capacity {
			clear()
			return
		}
		
		while size + headerSize > capacity {
			remove()
		}
		
		let h = hash(name)
		let i = index(h)
		
		let old = headerFields[i]
		let e = HeaderEntry(hash: h, name: name, value: value, index: head.before!.index - 1, next: old)
		headerFields[i] = e
		e.addBefore(head)
		size += headerSize
	}
	
	func getIndex(index: Int) -> Int {
		if index == -1 {
			return index
		}
		return index - head.before!.index + 1
	}
	
	func getIndex(name: [UInt8]) -> Int {
		if length == 0 || name.count == 0 {
			return -1
		}
		let h = hash(name)
		let i = self.index(h)
		var index = -1
		
		var e = headerFields[i]
			
		while let ee = e {
			
			if ee.hash == h && name == ee.name {
				index = ee.index
				break
			}
			
			e = ee.next
		}
		
		return getIndex(index)
	}
	
	func getEntry(name: [UInt8], value: [UInt8]) -> HeaderEntry? {
		if length == 0 || name.count == 0 || value.count == 0 {
			return nil
		}
		let h = hash(name)
		let i = index(h)
		
		var e = headerFields[i]
		
		while let ee = e {
			
			if ee.hash == h && name == ee.name && value == ee.value {
				return ee
			}
			e = ee.next
		}
		return nil
	}
	
	func getHeaderField(index: Int) -> HeaderField? {
		var entry = head
		var i = index
		while i >= 0 {
			i -= 1
			entry = entry.before!
		}
		return entry
	}
	
	func ensureCapacity(headerSize: Int) {
		while size + headerSize > capacity {
			if length == 0 {
				break
			}
			remove()
		}
	}
	
	func getNameIndex(name: [UInt8]) -> Int {
		var index = StaticTable.getIndex(name)
		if index == -1 {
			index = getIndex(name)
			if index >= 0 {
				index += StaticTable.length
			}
		}
		return index
	}

	func encodeInteger(out: Bytes, mask: Int, n: Int, i: Int) {
		let nbits = 0xFF >> (8 - n)
		if i < nbits {
			out.import8Bits(UInt8(mask | i))
		} else {
			out.import8Bits(UInt8(mask | nbits))
			var length = i - nbits
			while true {
				if (length & ~0x7F) == 0 {
					out.import8Bits(UInt8(length))
					return
				} else {
					out.import8Bits(UInt8((length & 0x7f) | 0x80))
					length >>= 7
				}
			}
		}
	}
	
	func encodeStringLiteral(out: Bytes, string: [UInt8]) throws {
		let huffmanLength = huffmanEncoderInstance.getEncodedLength(string)
		if huffmanLength < string.count {
			encodeInteger(out, mask: 0x80, n: 7, i: huffmanLength)
			try huffmanEncoderInstance.encode(out, input: Bytes(existingBytes: string))
		} else {
			encodeInteger(out, mask: 0x00, n: 7, i: string.count)
			out.importBytes(string)
		}
	}
	
	func encodeLiteral(out: Bytes, name: [UInt8], value: [UInt8], indexType: IndexType, nameIndex: Int) throws {
		var mask = 0
		var prefixBits = 0
		
		switch indexType {
		case .Incremental:
			mask = 0x40
			prefixBits = 6
		case .None:
			mask = 0x00
			prefixBits = 4
		case .Never:
			mask = 0x10
			prefixBits = 4
		}
		
		encodeInteger(out, mask: mask, n: prefixBits, i: nameIndex == -1 ? 0 : nameIndex)
		if nameIndex == -1 {
			try encodeStringLiteral(out, string: name)
		}
		try encodeStringLiteral(out, string: value)
	}

	func setMaxHeaderTableSize(out: Bytes, maxHeaderTableSize: Int) {
		if capacity == maxHeaderTableSize {
			return
		}
		capacity = maxHeaderTableSize
		ensureCapacity(0)
		encodeInteger(out, mask: 0x20, n: 5, i: maxHeaderTableSize)
	}
	
}

/// Decodes headers which have been HPACK encoded.
/// Decoding takes a HeaderListener object which receives each field/value as they are decoded.
public class HPACKDecoder {
	
	public enum Exception: ErrorType {
		case DecompressionException, IllegalIndexValue, InvalidMaxDynamicTableSize, MaxDynamicTableSizeChangeRequested
	}
	
	enum State {
		case ReadHeaderRepresentation, ReadMaxDynamicTableSize, ReadIndexedHeader, ReadIndexedHeaderName,
		ReadLiteralHeaderNameLengthPrefix, ReadLiteralHeaderNameLength, ReadLiteralHeaderName, SkipLiteralHeaderName,
		ReadLiteralHeaderValueLengthPrefix, ReadLiteralHeaderValueLength, ReadLiteralHeaderValue, SkipLiteralHeaderValue
	}
	
	static let empty = [UInt8]()
	
	let dynamicTable: DynamicTable
	
	let maxHeaderSize: Int
	var maxDynamicTableSize: Int
	var encoderMaxDynamicTableSize: Int
	
	var maxDynamicTableSizeChangeRequired: Bool
	
	var state: State
	
	var index = 0
	var headerSize = 0
	var indexType = IndexType.None
	var huffmanEncoded = false
	var name: [UInt8]?
	var skipLength = 0
	var nameLength = 0
	var valueLength = 0
	
	/// Construct an HPACKDecoder with the given memory constraints.
	public init(maxHeaderSize: Int = 256, maxHeaderTableSize: Int = 256) {
		self.dynamicTable = DynamicTable(initialCapacity: maxHeaderTableSize)
		self.maxHeaderSize = maxHeaderSize
		self.maxDynamicTableSize = maxHeaderTableSize
		self.encoderMaxDynamicTableSize = maxHeaderTableSize
		self.maxDynamicTableSizeChangeRequired = false
		self.state = .ReadHeaderRepresentation
	}
	
	func reset() {
		headerSize = 0
		state = .ReadHeaderRepresentation
		indexType = .None
	}
	
	func endHeaderBlock() -> Bool {
		let truncated = headerSize > maxHeaderSize
		reset()
		return truncated
	}
	
	func setMaxHeaderTableSize(maxHeaderTableSize: Int) {
		maxDynamicTableSize = maxHeaderTableSize
		if maxDynamicTableSize < encoderMaxDynamicTableSize {
			maxDynamicTableSizeChangeRequired = true
			dynamicTable.capacity = maxDynamicTableSize
		}
	}
	
	func getMaxHeaderTableSize() -> Int {
		return dynamicTable.capacity
	}
	
	var length: Int { return dynamicTable.length }
	var size: Int { return dynamicTable.size }
	
	func getHeaderField(index: Int) -> HeaderField {
		return dynamicTable.getEntry(index + 1)
	}
	
	func setDynamicTableSize(dynamicTableSize: Int) {
		encoderMaxDynamicTableSize = dynamicTableSize
		maxDynamicTableSizeChangeRequired = false
		dynamicTable.capacity = dynamicTableSize
	}
	
	func readName(index: Int) throws {
		if index <= StaticTable.length {
			name = StaticTable.getEntry(index).name
		} else if index - StaticTable.length <= dynamicTable.length {
			name = dynamicTable.getEntry(index - StaticTable.length).name
		} else {
			throw Exception.IllegalIndexValue
		}
	}
	
	func indexHeader(index: Int, headerListener: HeaderListener) throws {
		if index <= StaticTable.length {
			let headerField = StaticTable.getEntry(index)
			addHeader(headerListener, name: headerField.name, value: headerField.value, sensitive: false)
		} else if index - StaticTable.length <= dynamicTable.length {
			let headerField = dynamicTable.getEntry(index - StaticTable.length)
			addHeader(headerListener, name: headerField.name, value: headerField.value, sensitive: false)
		} else {
			throw Exception.IllegalIndexValue
		}
	}
	
	func addHeader(headerListener: HeaderListener, name: [UInt8], value: [UInt8], sensitive: Bool) {
		let newSize = headerSize + name.count + value.count
		if newSize <= maxHeaderSize {
			headerListener.addHeader(name, value: value, sensitive: sensitive)
			headerSize = newSize
		} else {
			headerSize = maxHeaderSize + 1
		}
	}
	
	func insertHeader(headerListener: HeaderListener, name: [UInt8], value: [UInt8], indexType: IndexType) {
		addHeader(headerListener, name: name, value: value, sensitive: indexType == .Never)
		switch indexType {
		case .None, .Never:
			()
		case .Incremental:
			dynamicTable.add(HeaderField(name: name, value: value))
		}
	}
	
	func exceedsMaxHeaderSize(size: Int) -> Bool {
		if size + headerSize <= maxHeaderSize {
			return false
		}
		headerSize = maxHeaderSize + 1
		return true
	}
	
	func readStringLiteral(input: Bytes, length: Int) throws -> [UInt8] {
		let read = input.exportBytes(length)
		if read.count != length {
			throw Exception.DecompressionException
		}
		if huffmanEncoded {
			return try huffmanDecoderInstance.decode(read)
		} else {
			return read
		}
	}
	
	func decodeULE128(input: Bytes) throws -> Int {
		let oldPos = input.position
		var result = 0
		var shift = 0
		while shift < 32 {
			if input.availableExportBytes == 0 {
				input.position = oldPos
				return -1
			}
			let b = input.export8Bits()
			if shift == 28 && (b & 0xF8) != 0 {
				break
			}
			result |= Int(b & 0x7F) << shift
			if (b & 0x80) == 0 {
				return result
			}
			shift += 7
		}
		input.position = oldPos
		throw Exception.DecompressionException
	}
	
	/// Decode the headers, sending them sequentially to headerListener.
	public func decode(input: Bytes, headerListener: HeaderListener) throws {
		while input.availableExportBytes > 0 {
			switch state {
			case .ReadHeaderRepresentation:
				let b = input.export8Bits()
				if maxDynamicTableSizeChangeRequired && (b & 0xE0) != 0x20 {
					throw Exception.MaxDynamicTableSizeChangeRequested
				}
				if (b & 0x80) != 0 { //b < 0 {
					index = Int(b & 0x7F)
					if index == 0 {
						throw Exception.IllegalIndexValue
					} else if index == 0x7F {
						state = .ReadIndexedHeader
					} else {
						try indexHeader(index, headerListener: headerListener)
					}
				} else if (b & 0x40) == 0x40 {
					indexType = .Incremental
					index = Int(b & 0x3F)
					if index == 0 {
						state = .ReadLiteralHeaderNameLengthPrefix
					} else if index == 0x3F {
						state = .ReadIndexedHeaderName
					} else {
						try readName(index)
						state = .ReadLiteralHeaderValueLengthPrefix
					}
				} else if (b & 0x20) == 0x20 {
					index = Int(b & 0x1F)
					if index == 0x1F {
						state = .ReadMaxDynamicTableSize
					} else {
						setDynamicTableSize(index)
						state = .ReadHeaderRepresentation
					}
				} else {
					indexType = (b & 0x10) == 0x10 ? .Never : .None
					index = Int(b & 0x0F)
					if index == 0 {
						state = .ReadLiteralHeaderNameLengthPrefix
					} else if index == 0x0F {
						state = .ReadIndexedHeaderName
					} else {
						try readName(index)
						state = .ReadLiteralHeaderValueLengthPrefix
					}
				}
				
			case .ReadMaxDynamicTableSize:
				let maxSize = try decodeULE128(input)
				if maxSize == -1 {
					return
				}
				if maxSize > HPACKEncoder.INDEX_MAX - index {
					throw Exception.DecompressionException
				}
				setDynamicTableSize(index + maxSize)
				state = .ReadHeaderRepresentation
			
			case .ReadIndexedHeader:
				let headerIndex = try decodeULE128(input)
				if headerIndex == -1 {
					return
				}
				if headerIndex > HPACKEncoder.INDEX_MAX - index {
					throw Exception.DecompressionException
				}
				try indexHeader(index + headerIndex, headerListener: headerListener)
				state = .ReadHeaderRepresentation
				
			case .ReadIndexedHeaderName:
				let nameIndex = try decodeULE128(input)
				if nameIndex == -1 {
					return
				}
				if nameIndex > HPACKEncoder.INDEX_MAX - index {
					throw Exception.DecompressionException
				}
				try readName(index + nameIndex)
				state = .ReadLiteralHeaderValueLengthPrefix
				
			case .ReadLiteralHeaderNameLengthPrefix:
				
				let b = input.export8Bits()
				huffmanEncoded = (b & 0x80) == 0x80
				index = Int(b & 0x7F)
				if index == 0x7F {
					state = .ReadLiteralHeaderNameLength
				} else {
					nameLength = index
					if nameLength == 0 {
						throw Exception.DecompressionException
					}
					if exceedsMaxHeaderSize(nameLength) {
						if indexType == .None {
							name = HPACKDecoder.empty
							skipLength = nameLength
							state = .SkipLiteralHeaderName
							break // check me
						}
						if nameLength + HeaderField.headerEntryOverhead > dynamicTable.capacity {
							dynamicTable.clear()
							name = HPACKDecoder.empty
							skipLength = nameLength
							state  = .SkipLiteralHeaderName
							break
						}
					}
					state = .ReadLiteralHeaderName
				}
			
			case .ReadLiteralHeaderNameLength:
				
				nameLength = try decodeULE128(input)
				if nameLength == -1 {
					return
				}
				if nameLength > HPACKEncoder.INDEX_MAX - index {
					throw Exception.DecompressionException
				}
				nameLength += index
				if exceedsMaxHeaderSize(nameLength) {
					if indexType == .None {
						name = HPACKDecoder.empty
						skipLength = nameLength
						state = .SkipLiteralHeaderName
						break // check me
					}
					if nameLength + HeaderField.headerEntryOverhead > dynamicTable.capacity {
						dynamicTable.clear()
						name = HPACKDecoder.empty
						skipLength = nameLength
						state  = .SkipLiteralHeaderName
						break
					}
				}
				state = .ReadLiteralHeaderName
			
			case .ReadLiteralHeaderName:
				
				if input.availableExportBytes < nameLength {
					return
				}
				
				name = try readStringLiteral(input, length: nameLength)
				state = .ReadLiteralHeaderValueLengthPrefix
				
			case .SkipLiteralHeaderName:
				
				let toSkip = min(skipLength, input.availableExportBytes)
				input.position += toSkip
				skipLength -= toSkip
				if skipLength == 0 {
					state = .ReadLiteralHeaderValueLengthPrefix
				}
				
			case .ReadLiteralHeaderValueLengthPrefix:
				
				let b = input.export8Bits()
				huffmanEncoded = (b & 0x80) == 0x80
				index = Int(b & 0x7F)
				if index == 0x7f {
					state = .ReadLiteralHeaderValueLength
				} else {
					valueLength = index
					let newHeaderSize = nameLength + valueLength
					if exceedsMaxHeaderSize(newHeaderSize) {
						headerSize = maxHeaderSize + 1
						if indexType == .None {
							state = .SkipLiteralHeaderValue
							break
						}
						if newHeaderSize + HeaderField.headerEntryOverhead > dynamicTable.capacity {
							dynamicTable.clear()
							state = .SkipLiteralHeaderValue
							break
						}
					}
					
					if valueLength == 0 {
						insertHeader(headerListener, name: name!, value: HPACKDecoder.empty, indexType: indexType)
						state = .ReadHeaderRepresentation
					} else {
						state = .ReadLiteralHeaderValue
					}
				}
				
			case .ReadLiteralHeaderValueLength:
				
				valueLength = try decodeULE128(input)
				if valueLength == -1 {
					return
				}
				if valueLength > HPACKEncoder.INDEX_MAX - index {
					throw Exception.DecompressionException
				}
				valueLength += index
				
				let newHeaderSize = nameLength + valueLength
				if newHeaderSize + headerSize > maxHeaderSize {
					headerSize = maxHeaderSize + 1
					if indexType == .None {
						state = .SkipLiteralHeaderValue
						break
					}
					if newHeaderSize + HeaderField.headerEntryOverhead > dynamicTable.capacity {
						dynamicTable.clear()
						state = .SkipLiteralHeaderValue
						break
					}
				}
				state = .ReadLiteralHeaderValue
				
			case .ReadLiteralHeaderValue:
				
				if input.availableExportBytes < valueLength {
					return
				}
				
				let value = try readStringLiteral(input, length: valueLength)
				insertHeader(headerListener, name: name!, value: value, indexType: indexType)
				state = .ReadHeaderRepresentation
				
			case .SkipLiteralHeaderValue:
				let toSkip = min(valueLength, input.availableExportBytes)
				input.position += toSkip
				valueLength -= toSkip
				if valueLength == 0 {
					state = .ReadHeaderRepresentation
				}
			}
		}
	}
}






















































