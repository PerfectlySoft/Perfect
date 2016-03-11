//
//  Bytes.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/7/15.
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

/// A Bytes object represents an array of UInt8 and provides various utilities for importing and exporting values into and out of that array.
/// A Bytes object maintains a position marker which is used to denote the position from which new export operations proceed.
/// An export will advance the position by the appropriate amount.
public class Bytes {
	
	/// The position from which new export operations begin.
	public var position = 0
	/// The underlying UInt8 array
	public var data: [UInt8]
	
	/// Indicates the number of bytes which may be successfully exported
	public var availableExportBytes: Int { return self.data.count - self.position }
	
	/// Create an empty Bytes object
	public init() {
		self.data = [UInt8]()
	}
	
	/// Initialize with existing bytes
	public init(existingBytes: [UInt8]) {
		self.data = existingBytes
	}
	
	/// Create a new Bytes object containing `initialSize` values of zero
	/// - parameter initialSize: The size of the initial array
	public init(initialSize: Int) {
		self.data = [UInt8](count: initialSize, repeatedValue: 0)
	}
	
	// -- IMPORT
	/// Imports one UInt8 value appending it to the end of the array
	/// - returns: The Bytes object
	public func import8Bits(byte: UInt8) -> Bytes {
		data.append(byte)
		return self
	}
	
	/// Imports one UInt16 value appending it to the end of the array
	/// - returns: The Bytes object
	public func import16Bits(short: UInt16) -> Bytes {
		data.append(UInt8(short & 0xFF))
		data.append(UInt8((short >> 8) & 0xFF))
		return self
	}
	
	/// Imports one UInt32 value appending it to the end of the array
	/// - returns: The Bytes object
	public func import32Bits(int: UInt32) -> Bytes {
		data.append(UInt8(int & 0xFF))
		data.append(UInt8((int >> 8) & 0xFF))
		data.append(UInt8((int >> 16) & 0xFF))
		data.append(UInt8((int >> 24) & 0xFF))
		return self
	}
	
	/// Imports one UInt64 value appending it to the end of the array
	/// - returns: The Bytes object
	public func import64Bits(int: UInt64) -> Bytes {
		data.append(UInt8(int & 0xFF))
		data.append(UInt8((int >> 8) & 0xFF))
		data.append(UInt8((int >> 16) & 0xFF))
		data.append(UInt8((int >> 24) & 0xFF))
		data.append(UInt8((int >> 32) & 0xFF))
		data.append(UInt8((int >> 40) & 0xFF))
		data.append(UInt8((int >> 48) & 0xFF))
		data.append(UInt8((int >> 56) & 0xFF))
		return self
	}
	
	/// Imports an array of UInt8 values appending them to the end of the array
	/// - returns: The Bytes object
	public func importBytes(bytes: [UInt8]) -> Bytes {
		data.appendContentsOf(bytes)
		return self
	}
	
	/// Imports the array values of the given Bytes appending them to the end of the array
	/// - returns: The Bytes object
	public func importBytes(bytes: Bytes) -> Bytes {
		data.appendContentsOf(bytes.data)
		return self
	}
	
	/// Imports an `ArraySlice` of UInt8 values appending them to the end of the array
	/// - returns: The Bytes object
	public func importBytes(bytes: ArraySlice<UInt8>) -> Bytes {
		data.appendContentsOf(bytes)
		return self
	}
	
	// -- EXPORT
	
	/// Exports one UInt8 from the current position. Advances the position marker by 1 byte.
	/// - returns: The UInt8 value
	public func export8Bits() -> UInt8 {
		let result = data[position]
		position += 1
		return result
	}
	
	/// Exports one UInt16 from the current position. Advances the position marker by 2 bytes.
	/// - returns: The UInt16 value
	public func export16Bits() -> UInt16 {

		let one = UInt16(data[position])
		position += 1
		let two = UInt16(data[position])
		position += 1
		
		return (two << 8) + one
	}
	
	/// Exports one UInt32 from the current position. Advances the position marker by 4 bytes.
	/// - returns: The UInt32 value
	public func export32Bits() -> UInt32 {
		let one = UInt32(data[position])
		position += 1
		let two = UInt32(data[position])
		position += 1
		let three = UInt32(data[position])
		position += 1
		let four = UInt32(data[position])
		position += 1
		
		return (four << 24) + (three << 16) + (two << 8) + one
	}
	
	/// Exports one UInt64 from the current position. Advances the position marker by 8 bytes.
	/// - returns: The UInt64 value
	public func export64Bits() -> UInt64 {
		let one = UInt64(data[position])
		position += 1
		let two = UInt64(data[position]) << 8
		position += 1
		let three = UInt64(data[position]) << 16
		position += 1
		let four = UInt64(data[position]) << 24
		position += 1
		let five = UInt64(data[position]) << 32
		position += 1
		let six = UInt64(data[position]) << 40
		position += 1
		let seven = UInt64(data[position]) << 48
		position += 1
		let eight = UInt64(data[position]) << 56
		position += 1
		
		return (one+two+three+four)+(five+six+seven+eight)
	}
	
	/// Exports the indicated number of bytes
	public func exportBytes(count: Int) -> [UInt8] {
		var sub = [UInt8]()
		let end = self.position + count
		while self.position < end {
			sub.append(self.data[self.position])
			self.position += 1
		}
		return sub
	}
}
















