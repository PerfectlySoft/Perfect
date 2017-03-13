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

#if os(Linux)
import LinuxBridge
#else
import Darwin
#endif

/// This class represents a directory on the file system.
/// It can be used for creating & inspecting directories and enumerating directory contents.
public struct Dir {
	/// A typealias for directory permission modes.
	public typealias PermissionMode = File.PermissionMode

	var internalPath = ""

	/// Create a new Dir object with the given path
	public init(_ path: String) {
		let pth = path.ends(with: "/") ? path : path + "/"
		self.internalPath = File.resolveTilde(inPath: pth)
	}

	/// Returns true if the directory exists
    public var exists: Bool {
		return exists(realPath)
	}

	/// Set this Dir as the process' working directory.
	public func setAsWorkingDir() throws {
		let res = chdir(self.internalPath)
		guard res == 0 else {
			try ThrowFileError()
		}
	}

	/// Return the process' current working directory.
	public static var workingDir: Dir {
		let buffer = Array(repeating: 0 as UInt8, count: 2049)
		let _ = getcwd(UnsafeMutableRawPointer(mutating: buffer).assumingMemoryBound(to: Int8.self), 2048)
		let path = String(validatingUTF8: UnsafeMutableRawPointer(mutating: buffer).assumingMemoryBound(to: Int8.self)) ?? "."
		return Dir(path)
	}

	func exists(_ path: String) -> Bool {
		return access(path, F_OK) != -1
	}

	/// Creates the directory using the provided permissions. All directories along the path will be created if need be.
	/// - parameter perms: The permissions for use for the new directory and preceeding directories which need to be created. Defaults to RWX-GUO
	/// - throws: `PerfectError.FileError`
	public func create(perms: PermissionMode = [.rwxUser, .rxGroup, .rxOther]) throws {
		let pth = realPath
		var currPath = pth.begins(with: "/") ? "/" : ""
		for component in pth.filePathComponents where component != "/" {
            currPath += component
            defer {
                currPath += "/"
            }
            guard !exists(currPath) else {
                continue
            }
            let res = mkdir(currPath, perms.rawValue)
            guard res != -1 else {
                try ThrowFileError()
            }
        }
	}

	/// Deletes the directory. The directory must be empty in order to be successfuly deleted.
	/// - throws: `PerfectError.FileError`
	public func delete() throws {
		let res = rmdir(realPath)
		guard res != -1 else {
			try ThrowFileError()
		}
	}

	/// Returns the name of the directory.
	public var name: String {
		return internalPath.lastFilePathComponent
	}

	/// Returns a Dir object representing the current Dir's parent. Returns nil if there is no parent.
	public var parentDir: Dir? {
		guard internalPath != "/" else {
			return nil // can not go up
		}
		return Dir(internalPath.deletingLastFilePathComponent)
	}

	/// Returns the path to the current directory.
	public var path: String {
		return internalPath
	}

	/// Returns the UNIX style permissions for the directory.
	public var perms: PermissionMode {
		get {
			return File(internalPath).perms
		}
		set {
			File(internalPath).perms = newValue
		}
	}

	var realPath: String {
		return internalPath.resolvingSymlinksInFilePath
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
	public func forEachEntry(closure: (String) throws -> ()) throws {
		guard let dir = opendir(realPath) else {
			try ThrowFileError()
		}

		defer { closedir(dir) }

		var ent = dirent()
		let entPtr = UnsafeMutablePointer<UnsafeMutablePointer<dirent>?>.allocate(capacity:  1)
		defer { entPtr.deallocate(capacity: 1) }

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
                guard let (_, elem) = childGen.next() else {
                    break
                }
				guard let elemI = elem as? Int8, elemI != 0 else {
					break
				}
				nameBuf.append(elemI)
			}
			nameBuf.append(0)
			if let name = String(validatingUTF8: nameBuf), !(name == "." || name == "..") {
                if Int32(type) == Int32(DT_DIR) {
                    try closure(name + "/")
                } else {
                    try closure(name)
                }
			}
		}
	}
}
