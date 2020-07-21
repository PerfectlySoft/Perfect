//
//  SysProcess.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/20/15.
//  Copyright (C) 2015 PerfectlySoft, Inc.
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
	public let SIGTERM = Int32(15)
#else
	import Darwin
#endif

/// This class permits an external process to be launched given a set of command line arguments and environment variables.
/// The standard in, out and err file streams are made available. The process can be terminated or permitted to be run to completion.
public class SysProcess {

	/// The standard in file stream.
	public var stdin: File?
	/// The standard out file stream.
	public var stdout: File?
	/// The standard err file stream.
	public var stderr: File?
	/// The process identifier.
	public var pid = pid_t(-1)
	/// The process group identifier.
	public var gid = pid_t(-1)

	/// Initialize the object and launch the process.
	/// - parameter cmd: The path to the process which will be launched.
	/// - parameter args: An optional array of String arguments which will be given to the process.
	/// - parameter env: An optional array of environment variable name and value pairs.
	/// - parameter newGroup: Create a new process group for this and all sub-processes. Default is no.
	/// - throws: `PerfectError.SystemError`
	public init(_ cmd: String, args: [String]?, env: [(String,String)]?, newGroup: Bool = false) throws {
		typealias maybeCChar = UnsafeMutablePointer<CChar>?
		
		let cArgsCount = args?.count ?? 0
		let cArgs = UnsafeMutablePointer<maybeCChar>.allocate(capacity: cArgsCount + 2)

		defer {
			cArgs.deinitialize(count: cArgsCount + 2)
			cArgs.deallocate()
		}

		cArgs[0] = strdup(cmd)
		cArgs[cArgsCount + 1] = nil
		
		for idx in 0..<cArgsCount {
			cArgs[idx+1] = strdup(args![idx])
		}

		let cEnvCount = env?.count ?? 0
		let cEnv = UnsafeMutablePointer<maybeCChar>.allocate(capacity: cEnvCount + 1)

		defer {
            cEnv.deinitialize(count: cEnvCount + 1)
            cEnv.deallocate()
        }

		cEnv[cEnvCount] = nil
		for idx in 0..<cEnvCount {
			cEnv[idx] = strdup(env![idx].0 + "=" + env![idx].1)
		}

		var fSTDIN: [Int32] = [0, 0]
		var fSTDOUT: [Int32] = [0, 0]
		var fSTDERR: [Int32] = [0, 0]

		fSTDIN.withUnsafeMutableBytes {
			_ = pipe($0.bindMemory(to: Int32.self).baseAddress)
		}
		fSTDOUT.withUnsafeMutableBytes {
			_ = pipe($0.bindMemory(to: Int32.self).baseAddress)
		}
		fSTDERR.withUnsafeMutableBytes {
			_ = pipe($0.bindMemory(to: Int32.self).baseAddress)
		}
    #if os(Linux)
		var action = posix_spawn_file_actions_t()
		var attr = posix_spawnattr_t()
    #else
		var action = posix_spawn_file_actions_t(nil as OpaquePointer?)
		var attr = posix_spawnattr_t(nil as OpaquePointer?)
    #endif

        // nerdo: This probably causes SysProcess to fail on tvOS, but it doesn't seem to be called in any of the
        // basic, core Perfect libraries, so this is probably a non-issue unless it is used directly
    #if os(tvOS)
        var procPid = pid_t()
        var spawnRes = 0
    #else
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
		
		posix_spawnattr_init(&attr)
		
		if newGroup {
			// By default, all flags are unset after the init call
			// so no need to OR in the existing flags.
			posix_spawnattr_setflags(&attr, Int16(POSIX_SPAWN_SETPGROUP))
		}

		var procPid = pid_t()
		let spawnRes = posix_spawnp(&procPid, cmd, &action, &attr, cArgs, cEnv)
		posix_spawn_file_actions_destroy(&action)
		posix_spawnattr_destroy(&attr)

		for idx in 0..<cArgsCount {
			free(cArgs[idx])
		}

		for idx in 0..<cEnvCount {
			free(cEnv[idx])
		}
    #endif

	#if os(Linux)
		// On Ubuntu the getpgid(pid_t) call does not seem to work.
		// However, the Posix standard says that the pgid is the same
		// as the pid of the first process spawned, so we can just use that.
		gid = procPid
		_ = SwiftGlibc.close(fSTDIN[0])
		_ = SwiftGlibc.close(fSTDOUT[1])
		_ = SwiftGlibc.close(fSTDERR[1])
		if spawnRes != 0 {
			_ = SwiftGlibc.close(fSTDIN[1])
			_ = SwiftGlibc.close(fSTDOUT[0])
			_ = SwiftGlibc.close(fSTDERR[0])
			try ThrowSystemError()
		}
	#else
		gid = Darwin.getpgid(procPid)
		_ = Darwin.close(fSTDIN[0])
		_ = Darwin.close(fSTDOUT[1])
		_ = Darwin.close(fSTDERR[1])
		if spawnRes != 0 {
			_ = Darwin.close(fSTDIN[1])
			_ = Darwin.close(fSTDOUT[0])
			_ = Darwin.close(fSTDERR[0])
			try ThrowSystemError()
		}
	#endif
		pid = procPid
		stdin = File("stdin", fd: fSTDIN[1])
		stdout = File("stdout", fd: fSTDOUT[0])
		stderr = File("stderr", fd: fSTDERR[0])
	}

	deinit {
		close()
	}

	/// Returns true if the process was opened and was running at some point.
	/// Note that the process may not be currently running. Use `wait(false)` to check if the process is currently running.
	public func isOpen() -> Bool {
		return pid != -1
	}

	/// Terminate the process and clean up.
	public func close() {
		if stdin != nil {
			stdin!.close()
		}
		if stdout != nil {
			stdout!.close()
		}
		if stderr != nil {
			stderr!.close()
		}
		if pid != -1 {
			do {
				let _ = try kill()
			} catch {

			}
		}
		stdin = nil
		stdout = nil
		stderr = nil
		pid = -1
		gid = -1
	}

	/// Detach from the process such that it will not be manually terminated when this object is deinitialized.
	public func detach() {
		pid = -1
	}

	/// Determine if the process has completed running and retrieve its result code.
	public func wait(hang: Bool = true) throws -> Int32 {
		var code = Int32(0)
		while true {
			let status = waitpid(pid, &code, WUNTRACED | (hang ? 0 : WNOHANG))
			if status == -1 && errno == EINTR {
				continue
			}
			guard status != -1 else {
				try ThrowSystemError()
			}
			if status == 0 && !hang {
				return 0
			}
			break
		}
		pid = -1
		return (((code) & 0xff00) >> 8)
	}

	/// Terminate the process and return its result code.
	public func kill(signal: Int32 = SIGTERM) throws -> Int32 {
	#if os(Linux)
		let status = SwiftGlibc.kill(pid, signal)
	#else
		let status = Darwin.kill(pid, signal)
	#endif
		guard status != -1 else {
			try ThrowSystemError()
		}
		return try wait()
	}
	
	/// Terminate the process group and return the root process result code.
	public func killGroup(signal: Int32 = SIGTERM) throws -> Int32 {
		#if os(Linux)
			let status = SwiftGlibc.killpg(gid, signal)
		#else
			let status = Darwin.killpg(gid, signal)
		#endif
		guard status != -1 else {
			try ThrowSystemError()
		}
		return try wait()
	}
}
