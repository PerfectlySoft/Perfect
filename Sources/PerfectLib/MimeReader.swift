//
//  MimeReader.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/6/15.
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
	import LinuxBridge
	let S_IRUSR = __S_IREAD
	let S_IROTH = (S_IRGRP >> 3)
	let S_IWOTH = (S_IWGRP >> 3)
#else
	import Darwin
#endif

enum MimeReadState {
	case StateNone
	case StateBoundary // next thing to be read will be a boundry
	case StateHeader // read header lines until data starts
	case StateFieldValue // read a simple value; name has already been set
	case StateFile // read file data until boundry
	case StateDone
}

let kMultiPartForm = "multipart/form-data"
let kBoundary = "boundary"

let kContentDisposition = "Content-Disposition"
let kContentType = "Content-Type"

let kPerfectTempPrefix = "perfect_upload_"

let mime_cr = UInt8(13)
let mime_lf = UInt8(10)
let mime_dash = UInt8(45)
//
//private extension Int {
//	func distanceTo(i: Int) -> Int { return i - self }
//	func advancedBy(i: Int) -> Int { return self + i }
//}

/// This class is responsible for reading multi-part POST form data, including handling file uploads.
/// Data can be given for parsing in little bits at a time by calling the `addTobuffer` function.
/// Any file uploads which are encountered will be written to the temporary directory indicated when the `MimeReader` is created.
/// Temporary files will be deleted when this object is deinitialized.
public class MimeReader {
	
	/// Array of BodySpecs representing each part that was parsed.
	public var bodySpecs = [BodySpec]()
	
	var maxFileSize = -1
	var (multi, gotFile) = (false, false)
	var buffer = [UInt8]()
	let tempDirectory: String
	var state: MimeReadState = .StateNone
	
	/// The boundary identifier.
	public var boundary = ""
	
	/// This class represents a single part of a multi-part POST submission
	public class BodySpec {
		/// The name of the form field.
		public var fieldName = ""
		/// The value for the form field.
		/// Having a fieldValue and a file are mutually exclusive.
		public var fieldValue = ""
		var fieldValueTempBytes: [UInt8]?
		/// The content-type for the form part.
		public var contentType = ""
		/// The client-side file name as submitted by the form.
		public var fileName = ""
		/// The size of the file which was submitted.
		public var fileSize = 0
		/// The name of the temporary file which stores the file upload on the server-side.
		public var tmpFileName = ""
		/// The File object for the local temporary file.
		public var file: File?
		
		init() {
		
		}
		
		/// Clean up the BodySpec, possibly closing and deleting any associated temporary file.
		public func cleanup() {
			if let f = self.file {
				if f.exists() {
					f.delete()
				}
				self.file = nil
			}
		}
		
		deinit {
			self.cleanup()
		}
	}
	
	/// Initialize given a Content-type header line.
	/// - parameter contentType: The Content-type header line.
	/// - parameter tempDir: The path to the directory in which to store temporary files. Defaults to "/tmp/".
	public init(_ contentType: String, tempDir: String = "/tmp/") {
		self.tempDirectory = tempDir
		if contentType.range(ofString: kMultiPartForm) != nil {
			self.multi = true
			if let range = contentType.range(ofString: kBoundary) {
				
				let startIndex = contentType.index(range.lowerBound, offsetBy: kBoundary.characters.count+1)
				let endIndex = contentType.endIndex
				
				let boundaryString = contentType.substring(with: startIndex..<endIndex)
				self.boundary.append("--")
				self.boundary.append(boundaryString)
				self.state = .StateBoundary
			}
		}
	}
	
// not implimented
//	public func setMaxFileSize(size: Int) {
//		self.maxFileSize = size
//	}
	
	func openTempFile(spec spec: BodySpec) {
		spec.file = File(tempFilePrefix: self.tempDirectory + kPerfectTempPrefix)
		spec.tmpFileName = spec.file!.path()
	}
	
	func isBoundaryStart(bytes bytes: [UInt8], start: Array<UInt8>.Index) -> Bool {
		var gen = self.boundary.utf8.makeIterator()
		var pos = start
		var next = gen.next()
		while let char = next {
			
			if pos == bytes.endIndex || char != bytes[pos] {
				return false
			}
			
			pos = pos.advanced(by: 1)
			next = gen.next()
		}
		return next == nil // got to the end is success
	}
	
	func isField(name name: String, bytes: [UInt8], start: Array<UInt8>.Index) -> Array<UInt8>.Index {
		var check = start
		let end = bytes.endIndex
		var gen = name.utf8.makeIterator()
		while check != end {
			if bytes[check] == 58 { // :
				return check
			}
			let gened = gen.next()
			
			if gened == nil {
				break
			}
			
			if tolower(Int32(gened!)) != tolower(Int32(bytes[check])) {
				break
			}
			
			check = check.advanced(by: 1)
		}
		return end
	}
	
	func pullValue(name name: String, from: String) -> String {
		
		var accum = ""
		
		if let nameRange = from.range(ofString: name + "=", ignoreCase: true) {
			var start = nameRange.upperBound
			let end = from.endIndex
			
			if from[start] == "\"" {
				start = from.index(after: start)
			}
			
			while start < end {
				if from[start] == "\"" || from[start] == ";" {
					break;
				}
				accum.append(from[start])
				start = from.index(after: start)
			}
		}
		return accum
	}
	
	func internalAddToBuffer(bytes bytes: [UInt8]) -> MimeReadState {
		
		var clearBuffer = true
		var position = bytes.startIndex
		let end = bytes.endIndex
		
		while position != end {
			switch self.state {
			case .StateDone, .StateNone:
				
				return .StateNone
				
			case .StateBoundary:
				
				if position.distance(to: end) < self.boundary.characters.count + 2 {
					self.buffer = Array(bytes[position..<end])
					clearBuffer = false
					position = end
				} else {
					position = position.advanced(by: self.boundary.characters.count)
					if bytes[position] == mime_dash && bytes[position.advanced(by: 1)] == mime_dash {
						self.state = .StateDone
						position = position.advanced(by: 2)
					} else {
						self.state = .StateHeader
						self.bodySpecs.append(BodySpec())
					}
					if self.state != .StateDone {
						position = position.advanced(by: 2) // line end
					} else {
						position = end
					}
				}
				
			case .StateHeader:
				
				var eolPos = position
				while eolPos.distance(to: end) > 1 {
					
					let b1 = bytes[eolPos]
					let b2 = bytes[eolPos.advanced(by: 1)]
					
					if b1 == mime_cr && b2 == mime_lf {
						break
					}
					eolPos = eolPos.advanced(by: 1)
				}
				if eolPos.distance(to: end) <= 1 { // no eol
					self.buffer = Array(bytes[position..<end])
					clearBuffer = false
					position = end
				} else {
					
					let spec = self.bodySpecs.last!
					if eolPos != position {
						
						let check = isField(name: kContentDisposition, bytes: bytes, start: position)
						if check != end { // yes, content-disposition
							
							let line = UTF8Encoding.encode(bytes: bytes[check.advanced(by: 2)..<eolPos])
							let name = pullValue(name: "name", from: line)
							let fileName = pullValue(name: "filename", from: line)
							
							spec.fieldName = name
							spec.fileName = fileName
							
						} else {
							
							let check = isField(name: kContentType, bytes: bytes, start: position)
							if check != end { // yes, content-type
								
								spec.contentType = UTF8Encoding.encode(bytes: bytes[check.advanced(by: 2)..<eolPos])
								
							}
						}
						position = eolPos.advanced(by: 2)
					}
					if (eolPos == position || position != end) && position.distance(to: end) > 1 && bytes[position] == mime_cr && bytes[position.advanced(by: 1)] == mime_lf {
						position = position.advanced(by: 2)
						if spec.fileName.characters.count > 0 {
							openTempFile(spec: spec)
							self.state = .StateFile
						} else {
							self.state = .StateFieldValue
							spec.fieldValueTempBytes = [UInt8]()
						}
					}
				}
			case .StateFieldValue:
				
				let spec = self.bodySpecs.last!
				while position != end {
					if bytes[position] == mime_cr {
						
						if position.distance(to: end) == 1 {
							self.buffer = Array(bytes[position..<end])
							clearBuffer = false
							position = end
							continue
						}
						
						if bytes[position.advanced(by: 1)] == mime_lf {
							
							if isBoundaryStart(bytes: bytes, start: position.advanced(by: 2)) {
								
								position = position.advanced(by: 2)
								self.state = .StateBoundary
								spec.fieldValue = UTF8Encoding.encode(bytes: spec.fieldValueTempBytes!)
								spec.fieldValueTempBytes = nil
								break
								
							} else if position.distance(to: end) - 2 < self.boundary.characters.count {
								// we are at the eol, but check to see if the next line may be starting a boundary
								if position.distance(to: end) < 4 || (bytes[position.advanced(by: 2)] == mime_dash && bytes[position.advanced(by: 3)] == mime_dash) {
									self.buffer = Array(bytes[position..<end])
									clearBuffer = false
									position = end
									continue
								}
							}
							
						}
					}
					
					spec.fieldValueTempBytes!.append(bytes[position])
					position = position.advanced(by: 1)
				}
				
			case .StateFile:
				
				let spec = self.bodySpecs.last!
				while position != end {
					if bytes[position] == mime_cr {
						
						if position.distance(to: end) == 1 {
							self.buffer = Array(bytes[position..<end])
							clearBuffer = false
							position = end
							continue
						}
						
						if bytes[position.advanced(by: 1)] == mime_lf {
							
							if isBoundaryStart(bytes: bytes, start: position.advanced(by: 2)) {
								
								position = position.advanced(by: 2)
								self.state = .StateBoundary
								
								// end of file data
								spec.file!.close()
								chmod(spec.file!.path(), mode_t(S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH))
								break
								
							} else if position.distance(to: end) - 2 < self.boundary.characters.count {
								// we are at the eol, but check to see if the next line may be starting a boundary
								if position.distance(to: end) < 4 || (bytes[position.advanced(by: 2)] == mime_dash && bytes[position.advanced(by: 3)] == mime_dash) {
									self.buffer = Array(bytes[position..<end])
									clearBuffer = false
									position = end
									continue
								}
							}
							
						}
					}
					// write as much data as we reasonably can
					var writeEnd = position
					while writeEnd < end {
						
						if bytes[writeEnd] == mime_cr {
							if writeEnd.distance(to: end) < 2 {
								break
							}
							if bytes[writeEnd.advanced(by: 1)] == mime_lf {
								if isBoundaryStart(bytes: bytes, start: writeEnd.advanced(by: 2)) {
									break
								} else if writeEnd.distance(to: end) - 2 < self.boundary.characters.count {
									// we are at the eol, but check to see if the next line may be starting a boundary
									if writeEnd.distance(to: end) < 4 || (bytes[writeEnd.advanced(by: 2)] == mime_dash && bytes[writeEnd.advanced(by: 3)] == mime_dash) {
										break
									}
								}
							}
						}
						
						writeEnd = writeEnd.advanced(by: 1)
					}
					do {
						let length = position.distance(to: writeEnd)
						spec.fileSize += try spec.file!.write(bytes: bytes, dataPosition: position, length: length)
					} catch let e {
						Log.error(message: "Exception while writing file upload data: \(e)")
						self.state = .StateNone
						break
					}
					
					if (writeEnd == end) {
						self.buffer.removeAll()
					}
					position = writeEnd
					self.gotFile = true
				}
			}
		}
		
		if clearBuffer {
			self.buffer.removeAll()
		}
		return self.state
	}
	
	/// Add data to be parsed.
	/// - parameter bytes: The array of UInt8 to be parsed.
	public func addToBuffer(bytes bytes: [UInt8]) {
		if isMultiPart() {
			
			if self.buffer.count != 0 {
				self.buffer.append(contentsOf: bytes)
				internalAddToBuffer(bytes: self.buffer)
			} else {
				internalAddToBuffer(bytes: bytes)
			}
		} else {
			self.buffer.append(contentsOf: bytes)
		}
	}
	
	/// Returns true of the content type indicated a multi-part form.
	public func isMultiPart() -> Bool {
		return self.multi
	}
}





