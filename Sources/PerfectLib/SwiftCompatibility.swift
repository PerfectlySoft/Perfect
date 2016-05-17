//
//  SwiftCompatibility.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2016-04-22.
//  Copyright © 2016 PerfectlySoft. All rights reserved.
//

#if swift(>=3.0)

	extension UnsafeMutablePointer {
		public static func allocatingCapacity(_ num: Int) -> UnsafeMutablePointer<Pointee> {
			return UnsafeMutablePointer<Pointee>(allocatingCapacity: num)
		}
	}
	
	extension String {
		func range(ofString string: String, ignoreCase: Bool = false) -> Range<String.Index>? {
			var idx = self.startIndex
			let endIdx = self.endIndex
			
			while idx != endIdx {
				if ignoreCase ? (String(self[idx]).lowercased() == String(string[string.startIndex]).lowercased()) : (self[idx] == string[string.startIndex]) {
					var newIdx = self.index(after: idx)
					var findIdx = string.index(after: string.startIndex)
					let findEndIdx = string.endIndex
					
					while newIdx != endIndex && findIdx != findEndIdx && (ignoreCase ? (String(self[newIdx]).lowercased() == String(string[findIdx]).lowercased()) : (self[newIdx] == string[findIdx])) {
						newIdx = self.index(after: newIdx)
						findIdx = string.index(after: findIdx)
					}
					
					if findIdx == findEndIdx { // match
						return idx..<newIdx
					}
				}
				idx = self.index(after: idx)
			}
			return nil
		}
	}
	
#else
	
	public typealias ErrorProtocol = ErrorType
	public typealias IteratorProtocol = GeneratorType
	public typealias UnicodeCodec = UnicodeCodecType
	public typealias Sequence = SequenceType
	public typealias OpaquePointer = COpaquePointer
	
	extension UnsafeMutablePointer {
	
		public static func allocatingCapacity(num: Int) -> UnsafeMutablePointer<Memory> {
			return UnsafeMutablePointer<Memory>.alloc(num)
		}
	
		var pointee: Memory {
			get { return self.memory }
			set { self.memory = newValue }
		}
		
		func deallocateCapacity(num: Int) {
			self.dealloc(num)
		}
		
		func deinitialize(count count: Int) {
			self.destroy(count)
		}
		
		func advanced(by by: Int) -> UnsafeMutablePointer<Memory> {
			return self.advancedBy(by)
		}
	}
	
	public extension String {
		init?(validatingUTF8: UnsafePointer<Int8>) {
			if let s = String.fromCString(validatingUTF8) {
				self.init(s)
			} else {
				return nil
			}
		}
		
		mutating func append(other: String) {
			self.appendContentsOf(other)
		}
		
		func lowercased() -> String {
			return self.lowercaseString
		}
		
		func uppercased() -> String {
			return self.uppercaseString
		}
		
		mutating func remove(at at: String.Index) -> Character {
			return self.removeAtIndex(at)
		}
		
		func substring(to index: String.Index) -> String {
			var s = ""
			var idx = self.startIndex
			let endIdx = self.endIndex
			while idx != endIdx && idx != index {
				s.append(self[idx])
				idx = self.index(after: idx)
			}
			return s
		}
		
		func substring(with range: Range<String.Index>) -> String {
			var s = ""
			var idx = range.lowerBound
			let endIdx = self.endIndex
			
			while idx < endIdx && idx < range.upperBound {
				s.append(self[idx])
				idx = self.index(after: idx)
			}
			
			return s
		}
		
		func index(after index: String.Index) -> String.Index {
			return index.successor()
		}
		
		func index(before index: String.Index) -> String.Index {
			return index.predecessor()
		}
		
		func index(_ index: String.Index, offsetBy: Int) -> String.Index {
			return index.advanced(by: offsetBy)
		}
		
		func range(ofString string: String, ignoreCase: Bool = false) -> Range<String.Index>? {
			var idx = self.startIndex
			let endIdx = self.endIndex
			
			while idx != endIdx {
				if ignoreCase ? (String(self[idx]).lowercased() == String(string[string.startIndex]).lowercased()) : (self[idx] == string[string.startIndex]) {
					var newIdx = self.index(after: idx)
					var findIdx = string.index(after: string.startIndex)
					let findEndIdx = string.endIndex
					
					while newIdx != endIndex && findIdx != findEndIdx && (ignoreCase ? (String(self[newIdx]).lowercased() == String(string[findIdx]).lowercased()) : (self[newIdx] == string[findIdx])) {
						newIdx = self.index(after: newIdx)
						findIdx = string.index(after: findIdx)
					}
					
					if findIdx == findEndIdx { // match
						return idx..<newIdx
					}
				}
				idx = self.index(after: idx)
			}
			return nil
		}
	}
	
	extension CollectionType where Generator == IndexingGenerator<Self> {
		public func makeIterator() -> IndexingGenerator<Self> {
			return self.generate()
		}
		
		public func suffix(from from: Self.Index) -> SubSequence {
			return self.suffixFrom(from)
		}
		
		func index(after index: String.Index) -> String.Index {
			return index.successor()
		}
	}
	
	extension String.CharacterView {
		func split(separator separator: Character, maxSplits: Int = Int.max, omittingEmptySubsequences: Bool = false) -> [String.CharacterView] {
			return self.split(separator, maxSplit: maxSplits, allowEmptySlices: false)
		}
		
		func index(after index: String.CharacterView.Index) -> String.CharacterView.Index {
			return index.successor()
		}
		
		func index(before index: String.CharacterView.Index) -> String.CharacterView.Index {
			return index.predecessor()
		}
	}
	
	extension String.UTF8View {
		func index(after index: String.UTF8View.Index) -> String.UTF8View.Index {
			return index.advanced(by: 1)
		}
	}
	
	extension String.UnicodeScalarView {
		public func makeIterator() -> Generator {
			return self.generate()
		}
	}
	
	extension String.CharacterView.Index {
		func advanced(by by: Int) -> String.CharacterView.Index {
			return self.advancedBy(by)
		}
	}
	
	extension String.UTF16View.Index {
		func advanced(by by: Int) -> String.UTF16View.Index {
			return self.advancedBy(by)
		}
	}
	
	extension String.UTF8View.Index {
		func advanced(by by: Int) -> String.UTF8View.Index {
			return self.advancedBy(by)
		}
	}
	
	extension Array {
		
		init(repeating: Generator.Element, count: Int) {
			self.init(count: count, repeatedValue: repeating)
		}
		
		mutating func append(contentsOf contentsOf: Array) {
			self.appendContentsOf(contentsOf)
		}
		
		mutating func append(contentsOf contentsOf: ArraySlice<Generator.Element>) {
			self.appendContentsOf(contentsOf)
		}
		
		mutating func remove(at at: Index) -> Element {
			return self.removeAtIndex(at)
		}
	}
	
	extension SequenceType where Generator.Element == String {
		@warn_unused_result
		public func joined(separator separator: String) -> String {
			return self.joinWithSeparator(separator)
		}
	}
	
	extension Dictionary {
		mutating func removeValue(forKey forKey: Key) -> Value? {
			return self.removeValueForKey(forKey)
		}
	}
	
	extension Int {
		func distance(to to: Int) -> Distance {
			return self.distanceTo(to)
		}
		func advanced(by by: Distance) -> Int {
			return self.advancedBy(by)
		}
	}
	
	extension COpaquePointer {
		public init<T>(bitPattern source: UnsafePointer<T>) {
			self.init(source)
		}
		
		/// Convert a typed `UnsafeMutablePointer` to an opaque C pointer.
		public init<T>(bitPattern source: UnsafeMutablePointer<T>) {
			self.init(source)
		}
	}
	
	extension RangeReplaceableCollectionType {
		public mutating func append<S : SequenceType where S.Generator.Element == Generator.Element>(contentsOf newElements: S) {
			return self.appendContentsOf(newElements)
		}
		
		public mutating func remove(at index: Self.Index) -> Self.Generator.Element {
			return self.removeAtIndex(index)
		}
	}
	
	extension Range {
		var lowerBound: Element { return self.startIndex }
		var upperBound: Element { return self.endIndex }
		
		init(uncheckedBounds: (Element, Element)) {
			self.init(start: uncheckedBounds.0, end: uncheckedBounds.1)
		}
	}
	
	@warn_unused_result
	public func unsafeBitCast<T, U>(x: T, to: U.Type) -> U {
		return unsafeBitCast(x, to)
	}
	
	
#endif
