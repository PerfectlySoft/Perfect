//
//  MimeReader.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/6/15.
//	Copyright (C) 2015 PerfectlySoft, Inc.
//
// ===----------------------------------------------------------------------===//
//
// This source file is part of the Perfect.org open source project
//
// Copyright (c) 2015 - 2016 PerfectlySoft Inc. and the Perfect project authors
// Licensed under Apache License v2.0
//
// See http://perfect.org/licensing.html for license information
//
// ===----------------------------------------------------------------------===//
//

#if os(Linux)
	import Foundation
	import LinuxBridge
	let S_IRUSR = __S_IREAD
	let S_IRGRP	= (S_IRUSR >> 3)
	let S_IWGRP	= (SwiftGlibc.S_IWUSR >> 3)
	let S_IROTH = (S_IRGRP >> 3)
	let S_IWOTH = (S_IWGRP >> 3)
#else
	import Darwin
#endif
import PerfectLib

enum MimeReadState {
	case stateNone
	case stateBoundary // next thing to be read will be a boundry
	case stateHeader // read header lines until data starts
	case stateFieldValue // read a simple value; name has already been set
	case stateFile // read file data until boundry
	case stateDone
}

let kMultiPartForm = "multipart/form-data"
let kBoundary = "boundary"

let kContentDisposition = "Content-Disposition"
let kContentType = "Content-Type"

let kPerfectTempPrefix = "perfect_upload_"

let mime_cr: UInt8 = 13
let mime_lf: UInt8 = 10
let mime_dash: UInt8 = 45

/// This class is responsible for reading multi-part POST form data, including handling file uploads.
/// Data can be given for parsing in little bits at a time by calling the `addTobuffer` function.
/// Any file uploads which are encountered will be written to the temporary directory indicated when the `MimeReader` is created.
/// Temporary files will be deleted when this object is deinitialized.
public final class MimeReader {

	/// Array of BodySpecs representing each part that was parsed.
	public var bodySpecs = [BodySpec]()

	var (multi, gotFile) = (false, false)
	var buffer = [UInt8]()
	let tempDirectory: String
	var state: MimeReadState = .stateNone

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
				if f.exists {
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
		if contentType.hasPrefix(kMultiPartForm) {
			self.multi = true
			if let range = contentType.range(of: kBoundary) {

				let startIndex = contentType.index(range.lowerBound, offsetBy: kBoundary.count+1)
				let endIndex = contentType.endIndex

				let boundaryString = String(contentType[startIndex..<endIndex])
				self.boundary.append("--")
				self.boundary.append(boundaryString)
				self.state = .stateBoundary
			}
		}
	}

	func openTempFile(spec spc: BodySpec) {
		spc.file = TemporaryFile(withPrefix: self.tempDirectory + kPerfectTempPrefix)
		spc.tmpFileName = spc.file!.path
	}

	func isBoundaryStart(bytes byts: [UInt8], start: Array<UInt8>.Index) -> Bool {
		var gen = self.boundary.utf8.makeIterator()
		var pos = start
		var next = gen.next()
		while let char = next {

			if pos == byts.endIndex || char != byts[pos] {
				return false
			}

			pos += 1
			next = gen.next()
		}
		return next == nil // got to the end is success
	}

	func isField(name nam: String, bytes: [UInt8], start: Array<UInt8>.Index) -> Array<UInt8>.Index {
		var check = start
		let end = bytes.endIndex
		var gen = nam.utf8.makeIterator()
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

	func pullValue(name nam: String, from: String) -> String {
		var accum = ""
		let option = String.CompareOptions.caseInsensitive
		if let nameRange = from.range(of: nam + "=", options: option) {
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

	@discardableResult
	func internalAddToBuffer(bytes byts: [UInt8]) -> MimeReadState {

		var clearBuffer = true
		var position = byts.startIndex
		let end = byts.endIndex

		while position != end {
			switch self.state {
			case .stateDone, .stateNone:

				return .stateNone

			case .stateBoundary:

				if position.distance(to: end) < boundary.count + 2 {
					buffer = Array(byts[position..<end])
					clearBuffer = false
					position = end
				} else {
					position = position.advanced(by: boundary.count)
					if byts[position] == mime_dash && byts[position.advanced(by: 1)] == mime_dash {
						self.state = .stateDone
						position = position.advanced(by: 2)
					} else {
						self.state = .stateHeader
						self.bodySpecs.append(BodySpec())
					}
					if self.state != .stateDone {
						position = position.advanced(by: 2) // line end
					} else {
						position = end
					}
				}

			case .stateHeader:

				var eolPos = position
				while eolPos.distance(to: end) > 1 {

					let b1 = byts[eolPos]
					let b2 = byts[eolPos.advanced(by: 1)]

					if b1 == mime_cr && b2 == mime_lf {
						break
					}
					eolPos = eolPos.advanced(by: 1)
				}
				if eolPos.distance(to: end) <= 1 { // no eol
					self.buffer = Array(byts[position..<end])
					clearBuffer = false
					position = end
				} else {

					let spec = self.bodySpecs.last!
					if eolPos != position {

						let check = isField(name: kContentDisposition, bytes: byts, start: position)
						if check != end { // yes, content-disposition

							let line = UTF8Encoding.encode(bytes: byts[check.advanced(by: 2)..<eolPos])
							let name = pullValue(name: "name", from: line)
							let fileName = pullValue(name: "filename", from: line)

							spec.fieldName = name
							spec.fileName = fileName

						} else {

							let check = isField(name: kContentType, bytes: byts, start: position)
							if check != end { // yes, content-type

								spec.contentType = UTF8Encoding.encode(bytes: byts[check.advanced(by: 2)..<eolPos])

							}
						}
						position = eolPos.advanced(by: 2)
					}
					if (eolPos == position || position != end) && position.distance(to: end) > 1 && byts[position] == mime_cr && byts[position.advanced(by: 1)] == mime_lf {
						position = position.advanced(by: 2)
						if spec.fileName.count > 0 {
							openTempFile(spec: spec)
							self.state = .stateFile
						} else {
							self.state = .stateFieldValue
							spec.fieldValueTempBytes = [UInt8]()
						}
					}
				}
			case .stateFieldValue:

				let spec = self.bodySpecs.last!
				while position != end {
					if byts[position] == mime_cr {

						if position.distance(to: end) == 1 {
							self.buffer = Array(byts[position..<end])
							clearBuffer = false
							position = end
							continue
						}

						if byts[position.advanced(by: 1)] == mime_lf {

							if isBoundaryStart(bytes: byts, start: position.advanced(by: 2)) {

								position = position.advanced(by: 2)
								self.state = .stateBoundary
								spec.fieldValue = UTF8Encoding.encode(bytes: spec.fieldValueTempBytes!)
								spec.fieldValueTempBytes = nil
								break

							} else if position.distance(to: end) - 2 < self.boundary.count {
								// we are at the eol, but check to see if the next line may be starting a boundary
								if position.distance(to: end) < 4 || (byts[position.advanced(by: 2)] == mime_dash && byts[position.advanced(by: 3)] == mime_dash) {
									self.buffer = Array(byts[position..<end])
									clearBuffer = false
									position = end
									continue
								}
							}

						}
					}

					spec.fieldValueTempBytes!.append(byts[position])
					position = position.advanced(by: 1)
				}

			case .stateFile:

				let spec = self.bodySpecs.last!
				while position != end {
					if byts[position] == mime_cr {

						if position.distance(to: end) == 1 {
							self.buffer = Array(byts[position..<end])
							clearBuffer = false
							position = end
							continue
						}

						if byts[position.advanced(by: 1)] == mime_lf {

							if isBoundaryStart(bytes: byts, start: position.advanced(by: 2)) {

								position = position.advanced(by: 2)
								self.state = .stateBoundary

								// end of file data
								spec.file!.close()
								#if os(Linux)
								chmod(spec.file!.path, mode_t(S_IRUSR|Int32(S_IWUSR)|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH))
								#else
								chmod(spec.file!.path, mode_t(S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH))
								#endif
								break

							} else if position.distance(to: end) - 2 < self.boundary.count {
								// we are at the eol, but check to see if the next line may be starting a boundary
								if position.distance(to: end) < 4 || (byts[position.advanced(by: 2)] == mime_dash && byts[position.advanced(by: 3)] == mime_dash) {
									self.buffer = Array(byts[position..<end])
									clearBuffer = false
									position = end
									continue
								}
							}
						}
					}
					// write as much data as we reasonably can
					var writeEnd = position
                    byts.withUnsafeBufferPointer { bufferedPointer in
                        if let qPtr = bufferedPointer.baseAddress {
                            while writeEnd < end {

                                if qPtr[writeEnd] == mime_cr {
                                    if end - writeEnd < 2 {
                                        break
                                    }
                                    if qPtr[writeEnd + 1] == mime_lf {
                                        if isBoundaryStart(bytes: byts, start: writeEnd + 2) {
                                            break
                                        } else if end - writeEnd - 2 < self.boundary.count {
                                            // we are at the eol, but check to see if the next line may be starting a boundary
                                            if end - writeEnd < 4 || (qPtr[writeEnd + 2] == mime_dash && qPtr[writeEnd + 3] == mime_dash) {
                                                break
                                            }
                                        }
                                    }
                                }

                                writeEnd += 1
                            }
                        }
                    }
					do {
						let length = writeEnd - position
						spec.fileSize += try spec.file!.write(bytes: byts, dataPosition: position, length: length)
					} catch let e {
						Log.error(message: "Exception while writing file upload data: \(e)")
						self.state = .stateNone
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
	public func addToBuffer(bytes byts: [UInt8]) {
		if isMultiPart {

			if self.buffer.count != 0 {
				self.buffer.append(contentsOf: byts)
				internalAddToBuffer(bytes: self.buffer)
			} else {
				internalAddToBuffer(bytes: byts)
			}
		} else {
			self.buffer.append(contentsOf: byts)
		}
	}

	/// Add data to be parsed.
	/// - parameter bytes: The array of UInt8 to be parsed.
	public func addToBuffer(bytes byts: UnsafePointer<UInt8>, length: Int) {
		if isMultiPart {
			if self.buffer.count != 0 {
				for i in 0..<length {
					self.buffer.append(byts[i])
				}
				internalAddToBuffer(bytes: self.buffer)
			} else {
				var a = [UInt8]()
				for i in 0..<length {
					a.append(byts[i])
				}
				internalAddToBuffer(bytes: a)
			}
		} else {
			for i in 0..<length {
				self.buffer.append(byts[i])
			}
		}
	}

	/// Returns true of the content type indicated a multi-part form.
	public var isMultiPart: Bool {
		return self.multi
	}
}
