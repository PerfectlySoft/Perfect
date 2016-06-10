//
//  Dir.swift
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

import Foundation

#if os(Linux)
import SwiftGlibc
import LinuxBridge
#else
import Darwin
#endif

/// This class represents a directory on the file system.
/// It can be used for creating & inspecting directories and enumerating directory contents.
public struct Dir {

	var internalPath = ""

	/// Create a new Dir object with the given path
	public init(_ path: String) {
		if path.ends(with: "/") {
			self.internalPath = path
		} else {
			self.internalPath = path + "/"
		}
	}

	/// Returns true if the directory exists
	public func exists() -> Bool {
		return exists(realPath())
	}

	func exists(_ path: String) -> Bool {
		return access(path, F_OK) != -1
	}

	/// Creates the directory using the provided permissions. All directories along the path will be created if need be.
	/// - parameter perms: The permissions for use for the new directory and preceeding directories which need to be created. Defaults to RWX-GUO
	/// - throws: `PerfectError.FileError`
	public func create(perms: Int = Int(S_IRWXG|S_IRWXU|S_IRWXO)) throws {
		let pth = realPath()
		var currPath = pth.begins(with: "/") ? "/" : ""

		for component in pth.pathComponents {
			if component != "/" {
				currPath += component
				if !exists(currPath) {
					let res = mkdir(currPath, mode_t(perms))
					guard res != -1 else {
						try ThrowFileError()
					}
				}
				currPath += "/"
			}
		}
	}

	/// Deletes the directory. The directory must be empty in order to be successfuly deleted.
	/// - throws: `PerfectError.FileError`
	public func delete() throws {
		let res = rmdir(realPath())
		guard res != -1 else {
			try ThrowFileError()
		}
	}

	/// Returns the name of the directory
	public func name() -> String {
		return internalPath.lastPathComponent
	}

	/// Returns a Dir object representing the current Dir's parent. Returns nil if there is no parent.
	public func parentDir() -> Dir? {
		guard internalPath != "/" else {
			return nil // can not go up
		}
		return Dir(internalPath.stringByDeletingLastPathComponent)
	}

	/// Returns the path to the current directory
	public func path() -> String {
		return internalPath
	}

	func realPath() -> String {
		return internalPath.stringByResolvingSymlinksInPath
	}

#if os(Linux)
    func readDir(_ d: OpaquePointer, _ dirEnt: inout dirent, _ endPtr: UnsafeMutablePointer<UnsafeMutablePointer<dirent>?>!) -> Int32 {
        return readdir_r(d, &dirEnt, endPtr)
    }
#else
    func readDir(_ d: UnsafeMutablePointer<DIR>, _ dirEnt: inout dirent, _ endPtr: UnsafeMutablePointer<UnsafeMutablePointer<dirent>?>!) -> Int32 {
        return readdir_r(d, &dirEnt, endPtr)
    }
#endif

	/// Enumerates the contents of the directory passing the name of each contained element to the provided callback.
	/// - parameter closure: The callback which will receive each entry's name
	/// - throws: `PerfectError.FileError`
	public func forEachEntry(closure: (name: String) -> ()) throws {
		guard let dir = opendir(realPath()) else {
			try ThrowFileError()
		}
            
		defer { closedir(dir) }

		var ent = dirent()
		let entPtr = UnsafeMutablePointer<UnsafeMutablePointer<dirent>?>(allocatingCapacity:  1)
		defer { entPtr.deallocateCapacity(1) }

		while readDir(dir, &ent, entPtr) == 0 && entPtr.pointee != nil {
			let name = ent.d_name
		#if os(Linux)
			let nameLen = 1024
		#else
			let nameLen = ent.d_namlen
		#endif
			let type = ent.d_type

			var nameBuf = [CChar]()
			let mirror = Mirror(reflecting: name)
			let childGen = mirror.children.makeIterator()
			for _ in 0..<nameLen {
				let (_, elem) = childGen.next()!
				if (elem as! Int8) == 0 {
					break
				}
				nameBuf.append(elem as! Int8)
			}
			nameBuf.append(0)
			if let name = String(validatingUTF8: nameBuf) {
				if !(name == "." || name == "..") {
					if Int32(type) == Int32(DT_DIR) {
						closure(name: name + "/")
					} else {
						closure(name: name)
					}
				}
			}
		}
	}
}
