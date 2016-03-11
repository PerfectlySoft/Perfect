//
//  SysProcess.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/20/15.
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
	let WUNTRACED = Int32(2)
	let WNOHANG = Int32(1)
	let SIGTERM = Int32(15)
#else
	import Darwin
#endif

/// This class permits an external process to be launched given a set of command line arguments and environment variables.
/// The standard in, out and err file streams are made available. The process can be terminated or permitted to be run to completion.
public class SysProcess : Closeable {
	
	/// The standard in file stream.
	public var stdin: File?
	/// The standard out file stream.
	public var stdout: File?
	/// The standard err file stream.
	public var stderr: File?
	/// The process identifier.
	public var pid = pid_t(-1)
	
	/// Initialize the object and launch the process.
	/// - parameter cmd: The path to the process which will be launched.
	/// - parameter args: An optional array of String arguments which will be given to the process.
	/// - parameter env: An optional array of environment variable name and value pairs.
	/// - throws: `LassoError.SystemError`
	public init(_ cmd: String, args: [String]?, env: [(String,String)]?) throws {
		let cArgsCount = args != nil ? args!.count : 0
		let cArgs = UnsafeMutablePointer<UnsafeMutablePointer<CChar>>.alloc(cArgsCount + 2)
		
		defer { cArgs.destroy() ; cArgs.dealloc(cArgsCount + 2) }
		
		cArgs[0] = strdup(cmd)
		cArgs[cArgsCount + 1] = UnsafeMutablePointer<CChar>(())
		var idx = 0
		while idx < cArgsCount {
			cArgs[idx+1] = strdup(args![idx])
			idx += 1
		}
		
		let cEnvCount = env != nil ? env!.count : 0
		let cEnv = UnsafeMutablePointer<UnsafeMutablePointer<CChar>>.alloc(cEnvCount + 1)
		
		defer { cEnv.destroy() ; cEnv.dealloc(cEnvCount + 1) }
		
		cEnv[cEnvCount] = UnsafeMutablePointer<CChar>(())
		idx = 0
		while idx < cEnvCount {
			cEnv[idx] = strdup(env![idx].0 + "=" + env![idx].1)
			idx += 1
		}
		
		let fSTDIN = UnsafeMutablePointer<Int32>.alloc(2)
		let fSTDOUT = UnsafeMutablePointer<Int32>.alloc(2)
		let fSTDERR = UnsafeMutablePointer<Int32>.alloc(2)
		
		defer {
			fSTDIN.destroy() ; fSTDIN.dealloc(2)
			fSTDOUT.destroy() ; fSTDOUT.dealloc(2)
			fSTDERR.destroy() ; fSTDERR.dealloc(2)
		}
		
		pipe(fSTDIN)
		pipe(fSTDOUT)
		pipe(fSTDERR)
		
		var action = posix_spawn_file_actions_t()
		
		posix_spawn_file_actions_init(&action);
		posix_spawn_file_actions_adddup2(&action, fSTDOUT[1], STDOUT_FILENO);
		posix_spawn_file_actions_adddup2(&action, fSTDIN[0], STDIN_FILENO);
		posix_spawn_file_actions_adddup2(&action, fSTDERR[1], STDERR_FILENO);
		
		posix_spawn_file_actions_addclose(&action, fSTDOUT[0]);
		posix_spawn_file_actions_addclose(&action, fSTDIN[0]);
		posix_spawn_file_actions_addclose(&action, fSTDERR[0]);
		posix_spawn_file_actions_addclose(&action, fSTDOUT[1]);
		posix_spawn_file_actions_addclose(&action, fSTDIN[1]);
		posix_spawn_file_actions_addclose(&action, fSTDERR[1]);
  
		var procPid = pid_t()
		let spawnRes = posix_spawnp(&procPid, cmd, &action, UnsafeMutablePointer<posix_spawnattr_t>(()), cArgs, cEnv)
		posix_spawn_file_actions_destroy(&action)
		
		idx = 0
		while idx < cArgsCount {
			free(cArgs[idx])
			idx += 1
		}
		
		idx = 0
		while idx < cEnvCount {
			free(cEnv[idx])
			idx += 1
		}

	#if os(Linux)
		SwiftGlibc.close(fSTDIN[0])
		SwiftGlibc.close(fSTDOUT[1])
		SwiftGlibc.close(fSTDERR[1])
		if spawnRes != 0 {
			SwiftGlibc.close(fSTDIN[1])
			SwiftGlibc.close(fSTDOUT[0])
			SwiftGlibc.close(fSTDERR[0])
			try ThrowSystemError()
		}
	#else
		Darwin.close(fSTDIN[0])
		Darwin.close(fSTDOUT[1])
		Darwin.close(fSTDERR[1])
		if spawnRes != 0 {
			Darwin.close(fSTDIN[1])
			Darwin.close(fSTDOUT[0])
			Darwin.close(fSTDERR[0])
			try ThrowSystemError()
		}
	#endif
		self.pid = procPid
		self.stdin = File(fd: fSTDIN[1], path: "")
		self.stdout = File(fd: fSTDOUT[0], path: "")
		self.stderr = File(fd: fSTDERR[0], path: "")
	}
	
	deinit {
		self.close()
	}
	
	/// Returns true if the process was opened and was running at some point.
	/// Note that the process may not be currently running. Use `wait(false)` to check if the process is currently running.
	public func isOpen() -> Bool {
		return self.pid != -1
	}
	
	/// Terminate the process and clean up.
	public func close() {
		if self.stdin != nil {
			self.stdin!.close()
		}
		if self.stdout != nil {
			self.stdout!.close()
		}
		if self.stderr != nil {
			self.stderr!.close()
		}
		if self.pid != -1 {
			do {
				try self.kill()
			} catch {
			
			}
		}
		self.stdin = nil
		self.stdout = nil
		self.stderr = nil
		self.pid = -1
	}
	
	/// Detach from the process such that it will not be manually terminated when this object is deinitialized.
	public func detach() {
		self.pid = -1
	}
	
	/// Determine if the process has completed running and retrieve its result code.
	public func wait(hang: Bool = true) throws -> Int32 {
		var code = Int32(0)
		let status = waitpid(self.pid, &code, WUNTRACED | (hang ? 0 : WNOHANG))
		if status == -1 {
			try ThrowSystemError()
		}
		self.pid = -1
		close()
		return code
	}
	
	/// Terminate the process and return its result code.
	public func kill(signal: Int32 = SIGTERM) throws -> Int32 {
	#if os(Linux)
		let status = SwiftGlibc.kill(self.pid, signal)
	#else
		let status = Darwin.kill(self.pid, signal)
	#endif
		guard status != -1 else {
			try ThrowSystemError()
		}
		return try self.wait()
	}
}




