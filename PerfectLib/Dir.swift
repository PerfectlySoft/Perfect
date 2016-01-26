//
//  Dir.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/7/15.
//	Copyright (C) 2015 PerfectlySoft, Inc.
//
//	This program is free software: you can redistribute it and/or modify
//	it under the terms of the GNU Affero General Public License as
//	published by the Free Software Foundation, either version 3 of the
//	License, or (at your option) any later version, as supplemented by the
//	Perfect Additional Terms.
//
//	This program is distributed in the hope that it will be useful,
//	but WITHOUT ANY WARRANTY; without even the implied warranty of
//	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//	GNU Affero General Public License, as supplemented by the
//	Perfect Additional Terms, for more details.
//
//	You should have received a copy of the GNU Affero General Public License
//	and the Perfect Additional Terms that immediately follow the terms and
//	conditions of the GNU Affero General Public License along with this
//	program. If not, see <http://www.perfect.org/AGPL_3_0_With_Perfect_Additional_Terms.txt>.
//

#if os(Linux)
import SwiftGlibc
	#else
import Darwin
#endif

/// This class represents a directory on the file system. 
/// It can be used for creating & inspecting directories and enumerating directory contents.
public class Dir {
	
	var internalPath = ""
	
	/// Create a new Dir object with the given path
	public init(_ path: String) {
		if path.hasSuffix("/") {
			self.internalPath = path
		} else {
			self.internalPath = path + "/"
		}
	}
	
	/// Returns true if the directory exists
	public func exists() -> Bool {
		return exists(realPath())
	}
	
	func exists(path: String) -> Bool {
		return access(path, F_OK) != -1
	}
	
	/// Creates the directory using the provided permissions. All directories along the path will be created if need be.
	/// - parameter perms: The permissions for use for the new directory and preceeding directories which need to be created. Defaults to RWX-GUO
	/// - throws: `PerfectError.FileError`
	public func create(perms: Int = Int(S_IRWXG|S_IRWXU|S_IRWXO)) throws {
		
		let pth = realPath()
		var currPath = pth.hasPrefix("/") ? "/" : ""
		
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
	
	/// Enumerates the contents of the directory passing the name of each contained element to the provided callback.
	/// - parameter closure: The callback which will receive each entry's name
	/// - throws: `PerfectError.FileError`
	public func forEachEntry(closure: (name: String) -> ()) throws {
		let dir = opendir(realPath())
		guard dir != nil else {
			try ThrowFileError()
		}
		defer { closedir(dir) }
		
		var ent = dirent()
		let entPtr = UnsafeMutablePointer<UnsafeMutablePointer<dirent>>.alloc(1)
		defer { entPtr.destroy() }
		
		while readdir_r(dir, &ent, entPtr) == 0 && entPtr.memory != nil {
			let name = ent.d_name
		#if os(Linux)
			let nameLen = 1024
		#else
			let nameLen = ent.d_namlen
		#endif
			let type = ent.d_type
			
			var nameBuf = [CChar]()
			let mirror = Mirror(reflecting: name)
			let childGen = mirror.children.generate()
			for _ in 0..<nameLen {
				let (_, elem) = childGen.next()!
				if (elem as! Int8) == 0 {
					break
				}
				nameBuf.append(elem as! Int8)
			}
			nameBuf.append(0)
			if let name = String.fromCString(nameBuf) {
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







