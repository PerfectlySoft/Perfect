//
//  MimeReader.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/6/15.
//
//

import Foundation

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

let kLassoTempPrefix = "lasso_upload_"

let mime_cr = UInt8(13)
let mime_lf = UInt8(10)
let mime_dash = UInt8(45)

/// This class is responsible for reading multi-part POST form data, including handling file uploads
public class MimeReader {
	
	public var bodySpecs = [BodySpec]()
	var maxFileSize = -1
	var (multi, gotFile) = (false, false)
	var buffer = [UInt8]()
	let tempDirectory: String
	var state: MimeReadState = .StateNone
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
	
	// We are given the Content-Type header line as a whole
	public init(_ contentType: String, tempDir: String = "/tmp/") {
		self.tempDirectory = tempDir
		if contentType.rangeOfString(kMultiPartForm) != nil {
			self.multi = true
			if let range = contentType.rangeOfString(kBoundary) {
				
				var startIndex = range.startIndex.successor()
				for _ in 1...kBoundary.characters.count {
					startIndex = startIndex.successor()
				}
				let endIndex = contentType.endIndex
				
				let boundaryString = contentType.substringWithRange(Range(start: startIndex, end: endIndex))
				self.boundary.appendContentsOf("--")
				self.boundary.appendContentsOf(boundaryString)
				self.state = .StateBoundary
			}
		}
	}
	
	public func setMaxFileSize(size: Int) {
		self.maxFileSize = size
	}
	
	func openTempFile(spec: BodySpec) {
		spec.file = File(tempFilePrefix: self.tempDirectory + kLassoTempPrefix)
		spec.tmpFileName = spec.file!.path()
	}
	
	func isBoundaryStart(bytes: [UInt8], start: Array<UInt8>.Index) -> Bool {
		var gen = self.boundary.utf8.generate()
		var pos = start
		var next = gen.next()
		while let char = next {
			
			if pos == bytes.endIndex || char != bytes[pos] {
				return false
			}
			
			pos = pos.successor()
			next = gen.next()
		}
		return next == nil // got to the end is success
	}
	
	func isField(name: String, bytes: [UInt8], start: Array<UInt8>.Index) -> Array<UInt8>.Index {
		var check = start
		let end = bytes.endIndex
		var gen = name.utf8.generate()
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
			
			check = check.successor()
		}
		return end
	}
	
	func pullValue(name: String, from: String) -> String {
		
		var accum = ""
		
		if let nameRange = from.rangeOfString(name + "=", options: NSStringCompareOptions.CaseInsensitiveSearch) {
			var start = nameRange.endIndex
			let end = from.endIndex
			
			if from[start] == "\"" {
				start = start.successor()
			}
			
			while start < end {
				if from[start] == "\"" || from[start] == ";" {
					break;
				}
				accum.append(from[start])
				start = start.successor()
			}
		}
		return accum
	}
	
	func internalAddToBuffer(inout bytes: [UInt8]) -> MimeReadState {
		
		var clearBuffer = true
		var position = bytes.startIndex
		let end = bytes.endIndex
		
		while position != end {
			switch self.state {
			case .StateDone, .StateNone:
				
				return .StateNone
				
			case .StateBoundary:
				
				if position.distanceTo(end) < self.boundary.characters.count + 2 {
					self.buffer = Array(bytes[position..<end])
					clearBuffer = false
					position = end
				} else {
					position = position.advancedBy(self.boundary.characters.count)
					if bytes[position] == mime_dash && bytes[position.successor()] == mime_dash {
						self.state = .StateDone
						position = position.advancedBy(2)
					} else {
						self.state = .StateHeader
						self.bodySpecs.append(BodySpec())
					}
					if self.state != .StateDone {
						position = position.advancedBy(2) // line end
					} else {
						position = end
					}
				}
				
			case .StateHeader:
				
				var eolPos = position
				while eolPos.distanceTo(end) > 1 {
					
					let b1 = bytes[eolPos]
					let b2 = bytes[eolPos.successor()]
					
					if b1 == mime_cr && b2 == mime_lf {
						break
					}
					eolPos = eolPos.successor()
				}
				if eolPos.distanceTo(end) <= 1 { // no eol
					self.buffer = Array(bytes[position..<end])
					clearBuffer = false
					position = end
				} else {
					
					let spec = self.bodySpecs.last!
					if eolPos != position {
						
						let check = isField(kContentDisposition, bytes: bytes, start: position)
						if check != end { // yes, content-disposition
							
							let line = UTF8Encoding.encode(bytes[check.advancedBy(2)..<eolPos])
							let name = pullValue("name", from: line)
							let fileName = pullValue("filename", from: line)
							
							spec.fieldName = name
							spec.fileName = fileName
							
						} else {
							
							let check = isField(kContentType, bytes: bytes, start: position)
							if check != end { // yes, content-type
								
								spec.contentType = UTF8Encoding.encode(bytes[check.advancedBy(2)..<eolPos])
								
							}
						}
						position = eolPos.advancedBy(2)
					}
					if (eolPos == position || position != end) && position.distanceTo(end) > 1 && bytes[position] == mime_cr && bytes[position.successor()] == mime_lf {
						position = position.advancedBy(2)
						if spec.fileName.characters.count > 0 {
							openTempFile(spec)
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
						
						if position.distanceTo(end) == 1 {
							self.buffer = Array(bytes[position..<end])
							clearBuffer = false
							position = end
							continue
						}
						
						if bytes[position.successor()] == mime_lf {
							
							if isBoundaryStart(bytes, start: position.advancedBy(2)) {
								
								position = position.advancedBy(2)
								self.state = .StateBoundary
								spec.fieldValue = UTF8Encoding.encode(spec.fieldValueTempBytes!)
								spec.fieldValueTempBytes = nil
								break
								
							} else if position.distanceTo(end) - 2 < self.boundary.characters.count {
								// we are at the eol, but check to see if the next line may be starting a boundary
								if position.distanceTo(end) < 4 || (bytes[position.advancedBy(2)] == mime_dash && bytes[position.advancedBy(3)] == mime_dash) {
									self.buffer = Array(bytes[position..<end])
									clearBuffer = false
									position = end
									continue
								}
							}
							
						}
					}
					
					spec.fieldValueTempBytes!.append(bytes[position])
					position = position.successor()
				}
				
			case .StateFile:
				
				let spec = self.bodySpecs.last!
				while position != end {
					if bytes[position] == mime_cr {
						
						if position.distanceTo(end) == 1 {
							self.buffer = Array(bytes[position..<end])
							clearBuffer = false
							position = end
							continue
						}
						
						if bytes[position.successor()] == mime_lf {
							
							if isBoundaryStart(bytes, start: position.advancedBy(2)) {
								
								position = position.advancedBy(2)
								self.state = .StateBoundary
								
								// end of file data
								spec.file!.close()
								Foundation.chmod(spec.file!.path(), S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH)
								break
								
							} else if position.distanceTo(end) - 2 < self.boundary.characters.count {
								// we are at the eol, but check to see if the next line may be starting a boundary
								if position.distanceTo(end) < 4 || (bytes[position.advancedBy(2)] == mime_dash && bytes[position.advancedBy(3)] == mime_dash) {
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
							if writeEnd.distanceTo(end) < 2 {
								break
							}
							if bytes[writeEnd.successor()] == mime_lf {
								if isBoundaryStart(bytes, start: writeEnd.advancedBy(2)) {
									break
								} else if writeEnd.distanceTo(end) - 2 < self.boundary.characters.count {
									// we are at the eol, but check to see if the next line may be starting a boundary
									if writeEnd.distanceTo(end) < 4 || (bytes[writeEnd.advancedBy(2)] == mime_dash && bytes[writeEnd.advancedBy(3)] == mime_dash) {
										break
									}
								}
							}
						}
						
						writeEnd = writeEnd.successor()
					}
					do {
						spec.fileSize += try spec.file!.writeBytes(bytes, dataPosition: position, length: position.distanceTo(writeEnd))
					} catch let e {
						print("Exception while writing file upload data: \(e)")
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
	
	public func addToBuffer(var bytes: [UInt8]) {
		if isMultiPart() {
			
			if self.buffer.count != 0 {
				self.buffer.appendContentsOf(bytes)
				internalAddToBuffer(&self.buffer)
			}
			
			internalAddToBuffer(&bytes)
		}
		self.buffer.appendContentsOf(bytes)
	}
	
	public func isMultiPart() -> Bool {
		return self.multi
	}
	
	public func gotFileupload() -> Bool {
		return false
	}
	
	
}





