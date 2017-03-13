//
//  File.swift
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
// !FIX! these are obviously sketchy
// I hope SwiftGlibc to eventually include these
// Otherwise, export them from LinuxBridge

import var Glibc.S_IRUSR
import var Glibc.S_IWUSR
import var Glibc.S_IXUSR
import var Glibc.S_IFMT
import var Glibc.S_IFREG
import var Glibc.S_IFDIR
import var Glibc.S_IFLNK

let S_IRGRP = (S_IRUSR >> 3)
let S_IWGRP	= (S_IWUSR >> 3)
let S_IXGRP	= (S_IXUSR >> 3)
let S_IRWXU = (__S_IREAD|__S_IWRITE|__S_IEXEC)
let S_IRWXG = (S_IRWXU >> 3)
let S_IRWXO = (S_IRWXG >> 3)
let S_IROTH = (S_IRGRP >> 3)
let S_IWOTH = (S_IWGRP >> 3)
let S_IXOTH = (S_IXGRP >> 3)

let SEEK_CUR: Int32 = 1
let EXDEV = Int32(18)
let EACCES = Int32(13)
let EAGAIN = Int32(11)
let F_OK: Int32 = 0

#else
import Darwin
#endif

let fileCopyBufferSize = 16384

/// Provides access to a file on the local file system
public class File {

	/// The underlying file system descriptor.
	public var fd = -1
	var internalPath = ""

    /// Checks that the file exists on the file system
    /// - returns: True if the file exists or false otherwise
    public var exists: Bool {
        return access(internalPath, F_OK) != -1
    }

    /// Returns true if the file has been opened
    public var isOpen: Bool {
        return fd != -1
    }

    /// Returns the file's path
    public var path: String { return internalPath }

    /// Returns the file path. If the file is a symbolic link, the link will be resolved.
    public var realPath: String {
        let maxPath = 2048
        guard isLink else {
            return internalPath
        }
        var ary = [UInt8](repeating: 0, count: maxPath)
		let buffer = UnsafeMutableRawPointer(mutating: ary).assumingMemoryBound(to: Int8.self)
        let res = readlink(internalPath, buffer, maxPath)
        guard res != -1 else {
            return internalPath
        }
        ary.removeLast(maxPath - res)
        let trailPath = UTF8Encoding.encode(bytes: ary)
        let lastChar = trailPath[trailPath.startIndex]
        guard lastChar != "/" && lastChar != "." else {
            return trailPath
        }
        return internalPath.deletingLastFilePathComponent + "/" + trailPath
    }

    /// Returns the modification date for the file in the standard UNIX format of seconds since 1970/01/01 00:00:00 GMT
    /// - returns: The date as Int
    public var modificationTime: Int {
        var st = stat()
        let res = isOpen ?  fstat(Int32(fd), &st) : stat(internalPath, &st)
        guard res == 0 else {
            return Int.max
        }
        #if os(Linux)
            return Int(st.st_mtim.tv_sec)
        #else
            return Int(st.st_mtimespec.tv_sec)
        #endif
    }

	static func resolveTilde(inPath: String) -> String {
		if !inPath.isEmpty && inPath[inPath.startIndex] == "~" {
			var wexp = wordexp_t()
			guard 0 == wordexp(inPath, &wexp, 0),
					let we_wordv = wexp.we_wordv else {
				return inPath
			}
			defer {
				wordfree(&wexp)
			}
			if let resolved = we_wordv[0], let pth = String(validatingUTF8: resolved) {
				return pth
			}
		}
		return inPath
	}

	/// Create a file object given a path and open mode
	/// - parameter path: Path to the file which will be accessed
    /// - parameter fd: The file descriptor, if any, for an already opened file
	public init(_ path: String, fd: Int32 = -1) {
		self.internalPath = File.resolveTilde(inPath: path)
        self.fd = Int(fd)
	}

	deinit {
		close()
	}
	
	/// Closes the file if it had been opened
	public func close() {
		if fd != -1 {
		#if os(Linux)
			_ = SwiftGlibc.close(CInt(fd))
		#else
            _ = Darwin.close(CInt(fd))
		#endif
			fd = -1
		}
	}

	/// Resets the internal file descriptor, leaving the file opened if it had been.
	public func abandon() {
		fd = -1
	}
}

public extension File {
    /// The open mode for the file.
    public enum OpenMode {
        /// Opens the file for read-only access.
        case read
        /// Opens the file for write-only access, creating the file if it did not exist.
        case write
        /// Opens the file for read-write access, creating the file if it did not exist.
        case readWrite
        /// Opens the file for read-write access, creating the file if it did not exist and moving the file marker to the end.
        case append
        /// Opens the file for read-write access, creating the file if it did not exist and setting the file's size to zero.
        case truncate

        var toMode: Int {
            switch self {
            case .read:         return Int(O_RDONLY)
            case .write:        return Int(O_WRONLY|O_CREAT)
            case .readWrite:    return Int(O_RDWR|O_CREAT)
            case .append:       return Int(O_RDWR|O_APPEND|O_CREAT)
            case .truncate:     return Int(O_RDWR|O_TRUNC|O_CREAT)
            }
        }
    }
	/// A file or directory access permission value.
	public struct PermissionMode: OptionSet {
		/// File system mode type.
		public typealias Mode = mode_t
		/// The raw mode.
		public let rawValue: Mode
		/// Create a permission mode with a raw value.
		public init(rawValue: Mode) {
			self.rawValue = rawValue
		}

#if os(Linux)
		init(rawValue: Int32) {
			self.init(rawValue: UInt32(rawValue))
		}
#endif

		/// Readable by user.
		public static let readUser = PermissionMode(rawValue: S_IRUSR)
		/// Writable by user.
		public static let writeUser = PermissionMode(rawValue: S_IWUSR)
		/// Executable by user.
		public static let executeUser = PermissionMode(rawValue: S_IXUSR)
		/// Readable by group.
		public static let readGroup = PermissionMode(rawValue: S_IRGRP)
		/// Writable by group.
		public static let writeGroup = PermissionMode(rawValue: S_IWGRP)
		/// Executable by group.
		public static let executeGroup = PermissionMode(rawValue: S_IXGRP)
		/// Readable by others.
		public static let readOther = PermissionMode(rawValue: S_IROTH)
		/// Writable by others.
		public static let writeOther = PermissionMode(rawValue: S_IWOTH)
		/// Executable by others.
		public static let executeOther = PermissionMode(rawValue: S_IXOTH)

		/// Read, write, execute by user.
		public static let rwxUser: PermissionMode = [.readUser, .writeUser, .executeUser]
		/// Read, write by user and group.
		public static let rwUserGroup: PermissionMode = [.readUser, .writeUser, .readGroup, .writeGroup]

		/// Read, execute by group.
		public static let rxGroup: PermissionMode = [.readGroup, .executeGroup]
		/// Read, execute by other.
		public static let rxOther: PermissionMode = [.readOther, .executeOther]

	}

	/// Opens the file using the given mode.
	/// - throws: `PerfectError.FileError`
	public func open(_ mode: OpenMode = .read, permissions: PermissionMode = .rwUserGroup) throws {
        if fd != -1 {
            close()
        }
	#if os(Linux)
		let openFd = linux_open(internalPath, CInt(mode.toMode), permissions.rawValue)
	#else
		let openFd = Darwin.open(internalPath, CInt(mode.toMode), permissions.rawValue)
	#endif
		guard openFd != -1 else {
			try ThrowFileError()
		}
		fd = Int(openFd)
	}
}

public extension File {
    /// The current file read/write position.
    public var marker: Int {
        /// Returns the value of the file's current position marker
        get {
            if isOpen {
                return Int(lseek(Int32(self.fd), 0, SEEK_CUR))
            }
            return 0
        }
        /// Sets the file's position marker given the value as measured from the begining of the file.
        set {
            lseek(Int32(self.fd), off_t(newValue), SEEK_SET)
        }
    }
}

public extension File {

    /// Closes and deletes the file
    public func delete() {
        close()
        unlink(path)
    }

    /// Moves the file to the new location, optionally overwriting any existing file
    /// - parameter path: The path to move the file to
    /// - parameter overWrite: Indicates that any existing file at the destination path should first be deleted
    /// - returns: Returns a new file object representing the new location
    /// - throws: `PerfectError.FileError`
    public func moveTo(path: String, overWrite: Bool = false) throws -> File {
        let destFile = File(path)
        if destFile.exists {
            guard overWrite else {
                throw PerfectError.fileError(-1, "Can not overwrite existing file")
            }
            destFile.delete()
        }
        close()
        let res = rename(self.path, path)
        if res == 0 {
            return destFile
        }
        if errno == EXDEV {
            _ = try self.copyTo(path: path, overWrite: overWrite)
            self.delete()
            return destFile
        }
        try ThrowFileError()
    }

    /// Copies the file to the new location, optionally overwriting any existing file
    /// - parameter path: The path to copy the file to
    /// - parameter overWrite: Indicates that any existing file at the destination path should first be deleted
    /// - returns: Returns a new file object representing the new location
    /// - throws: `PerfectError.FileError`
    @discardableResult
    public func copyTo(path pth: String, overWrite: Bool = false) throws -> File {
        let destFile = File(pth)
        if destFile.exists {
            guard overWrite else {
                throw PerfectError.fileError(-1, "Can not overwrite existing file")
            }
            destFile.delete()
        }
        let wasOpen = self.isOpen
        let oldMarker = self.marker
        if !wasOpen {
            try open()
        } else {
            _ = marker = 0
        }
        defer {
            if !wasOpen {
                close()
            } else {
                _ = marker = oldMarker
            }
        }

        try destFile.open(.truncate)

        var bytes = try self.readSomeBytes(count: fileCopyBufferSize)
        while bytes.count > 0 {
            try destFile.write(bytes: bytes)
            bytes = try self.readSomeBytes(count: fileCopyBufferSize)
        }

        destFile.close()
        return destFile
    }
}

public extension File {

	/// Returns the size of the file in bytes
    public var size: Int {
		var st = stat()
		let statRes = isOpen ?  fstat(Int32(fd), &st) : stat(internalPath, &st)
		guard statRes != -1 else {
			return 0
		}
		return Int(st.st_size)
	}

	/// Returns true if the file is actually a directory
    public var isDir: Bool {
		var st = stat()
		let statRes = isOpen ?  fstat(Int32(fd), &st) : stat(internalPath, &st)
		guard statRes != -1 else {
			return false
		}
		let mode = st.st_mode
		return (Int32(mode) & Int32(S_IFMT)) == Int32(S_IFDIR)
	}

	/// Returns the UNIX style permissions for the file
    public var perms: PermissionMode {
		get {
			var st = stat()
			let statRes = isOpen ?  fstat(Int32(fd), &st) : stat(internalPath, &st)
			guard statRes != -1 else {
				return PermissionMode(rawValue: PermissionMode.Mode(0))
			}
			let mode = st.st_mode
			return PermissionMode(rawValue: mode_t(Int32(mode) ^ Int32(S_IFMT)))
		}
		set {
			_ = chmod(internalPath, newValue.rawValue)
		}
    }
}

public extension File {
	/// Returns true if the file is a symbolic link
	public var isLink: Bool {
		var st = stat()
		let statRes = lstat(internalPath, &st)
		guard statRes != -1 else {
			return false
		}
		let mode = st.st_mode
		return (Int32(mode) & Int32(S_IFMT)) == Int32(S_IFLNK)
	}
	
	/// Create a symlink from the target to the destination.
	@discardableResult
	public func linkTo(path: String, overWrite: Bool = false) throws -> File {
		let destFile = File(path)
		if destFile.exists {
			guard overWrite else {
				throw PerfectError.fileError(-1, "Can not overwrite existing file")
			}
			destFile.delete()
		}
		let res = symlink(self.path, path)
		if res == 0 {
			return File(path)
		}
		try ThrowFileError()
	}
}

public extension File {

	/// Reads up to the indicated number of bytes from the file
	/// - parameter count: The maximum number of bytes to read
	/// - returns: The bytes read as an array of UInt8. May have a count of zero.
	/// - throws: `PerfectError.FileError`
	public func readSomeBytes(count: Int) throws -> [UInt8] {
        if !isOpen {
            try open()
        }

        func sizeOr(_ value: Int) -> Int {
            var st = stat()
            let statRes = isOpen ?  fstat(Int32(fd), &st) : stat(internalPath, &st)
            guard statRes != -1 else {
                return 0
            }
            if (Int32(st.st_mode) & Int32(S_IFMT)) == Int32(S_IFREG) {
                return Int(st.st_size)
            }
            return value
        }

		let bSize = min(count, sizeOr(count))
		var ary = [UInt8](repeating: 0, count: bSize)
		let ptr = UnsafeMutableRawPointer(mutating: ary).assumingMemoryBound(to: Int8.self)

		let readCount = read(CInt(fd), ptr, bSize)
		guard readCount >= 0 else {
			try ThrowFileError()
		}
		if readCount < bSize {
			ary.removeLast(bSize - readCount)
		}
		return ary
	}

	/// Reads the entire file as a string
	public func readString() throws -> String {
		let bytes = try self.readSomeBytes(count: self.size)
		return UTF8Encoding.encode(bytes: bytes)
    }
}

public extension File {

	/// Writes the string to the file using UTF-8 encoding
	/// - parameter s: The string to write
	/// - returns: Returns the number of bytes which were written
	/// - throws: `PerfectError.FileError`
    @discardableResult
	public func write(string: String) throws -> Int {
		return try write(bytes: Array(string.utf8))
	}

	/// Write the indicated bytes to the file
	/// - parameter bytes: The array of UInt8 to write.
	/// - parameter dataPosition: The offset within `bytes` at which to begin writing.
	/// - parameter length: The number of bytes to write.
	/// - throws: `PerfectError.FileError`
    @discardableResult
	public func write(bytes: [UInt8], dataPosition: Int = 0, length: Int = Int.max) throws -> Int {
        let len = min(bytes.count - dataPosition, length)
		let ptr = UnsafeMutableRawPointer(mutating: bytes).assumingMemoryBound(to: UInt8.self).advanced(by: dataPosition)
    #if os(Linux)
		let wrote = SwiftGlibc.write(Int32(fd), ptr, len)
	#else
		let wrote = Darwin.write(Int32(fd), ptr, len)
	#endif
		guard wrote == len else {
			try ThrowFileError()
		}
		return wrote
	}
}

public extension File {

	/// Attempts to place an advisory lock starting from the current position marker up to the indicated byte count. This function will block the current thread until the lock can be performed.
	/// - parameter byteCount: The number of bytes to lock
	/// - throws: `PerfectError.FileError`
	public func lock(byteCount: Int) throws {
		if !isOpen {
			try open(.write)
		}
		let res = lockf(Int32(self.fd), F_LOCK, off_t(byteCount))
		guard res == 0 else {
			try ThrowFileError()
		}
	}

	/// Unlocks the number of bytes starting from the current position marker up to the indicated byte count.
	/// - parameter byteCount: The number of bytes to unlock
	/// - throws: `PerfectError.FileError`
	public func unlock(byteCount: Int) throws {
		if !isOpen {
			try open(.write)
		}
		let res = lockf(Int32(self.fd), F_ULOCK, off_t(byteCount))
		guard res == 0 else {
			try ThrowFileError()
		}
	}

	/// Attempts to place an advisory lock starting from the current position marker up to the indicated byte count. This function will throw an exception if the file is already locked, but will not block the current thread.
	/// - parameter byteCount: The number of bytes to lock
	/// - throws: `PerfectError.FileError`
	public func tryLock(byteCount: Int) throws {
		if !isOpen {
			try open(.write)
		}
		let res = lockf(Int32(self.fd), F_TLOCK, off_t(byteCount))
		guard res == 0 else {
			try ThrowFileError()
		}
	}

	/// Tests if the indicated bytes are locked
	/// - parameter byteCount: The number of bytes to test
	/// - returns: True if the file is locked
	/// - throws: `PerfectError.FileError`
	public func testLock(byteCount: Int) throws -> Bool {
		if !isOpen {
			try open(.write)
		}
		let res = Int(lockf(Int32(self.fd), F_TEST, off_t(byteCount)))
		guard res == 0 || res == Int(EACCES) || res == Int(EAGAIN) else {
			try ThrowFileError()
		}
		return res != 0
	}
}

// Subclass to represent a file which can not be closed
private final class UnclosableFile : File {
    override init(_ path: String, fd: Int32) {
		super.init(path, fd: fd)
	}
	override func close() {
		// nothing
	}
}

/// A temporary, randomly named file.
public final class TemporaryFile: File {
    /// Create a temporary file, usually in the system's /tmp/ directory
    /// - parameter withPrefix: The prefix for the temporary file's name. Random characters will be appended to the file's eventual name.
    public convenience init(withPrefix: String) {
        let template = withPrefix + "XXXXXX"
        let utf8 = template.utf8
        let name = UnsafeMutablePointer<Int8>.allocate(capacity: utf8.count + 1)
        var i = utf8.startIndex
        for index in 0..<utf8.count {
            name[index] = Int8(utf8[i])
            i = utf8.index(after: i)
        }
        name[utf8.count] = 0

        let fd = mkstemp(name)
        let tmpFileName = String(validatingUTF8: name)!

        name.deallocate(capacity: utf8.count + 1)

        self.init(tmpFileName, fd: fd)
    }
}

/// This file can be used to write to standard in
public var fileStdin: File {
    return UnclosableFile("/dev/stdin", fd: STDIN_FILENO)
}

/// This file can be used to write to standard out
public var fileStdout: File {
	return UnclosableFile("/dev/stdout", fd: STDOUT_FILENO)
}

/// This file can be used to write to standard error
public var fileStderr: File {
	return UnclosableFile("/dev/stderr", fd: STDERR_FILENO)
}
