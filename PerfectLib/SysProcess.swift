//
//  SysProcess.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/20/15.
//
//

import Foundation

public class SysProcess : Closeable {
	
	public var stdin: File?
	public var stdout: File?
	public var stderr: File?
	public var pid = pid_t(-1)
	
	public init(_ cmd: String, args: [String]?, env: [(String,String)]?) throws {
		let cArgsCount = args != nil ? args!.count : 0
		let cArgs = UnsafeMutablePointer<UnsafeMutablePointer<CChar>>.alloc(cArgsCount + 2)
		
		defer { cArgs.destroy() ; cArgs.dealloc(cArgsCount + 2) }
		
		cArgs[0] = strdup(cmd)
		cArgs[cArgsCount + 1] = UnsafeMutablePointer<CChar>(())
		var idx = 0
		for (; idx < cArgsCount; ++idx) {
			cArgs[idx+1] = strdup(args![idx])
		}
		
		let cEnvCount = env != nil ? env!.count : 0
		let cEnv = UnsafeMutablePointer<UnsafeMutablePointer<CChar>>.alloc(cEnvCount + 1)
		
		defer { cEnv.destroy() ; cEnv.dealloc(cEnvCount + 1) }
		
		cEnv[cEnvCount] = UnsafeMutablePointer<CChar>(())
		idx = 0
		for (; idx < cEnvCount; ++idx) {
			cEnv[idx] = strdup(env![idx].0 + "=" + env![idx].1)
		}
		
		let fSTDIN = UnsafeMutablePointer<Int32>.alloc(2)
		let fSTDOUT = UnsafeMutablePointer<Int32>.alloc(2)
		let fSTDERR = UnsafeMutablePointer<Int32>.alloc(2)
		
		defer {
			fSTDIN.destroy() ; fSTDIN.dealloc(2)
			fSTDOUT.destroy() ; fSTDOUT.dealloc(2)
			fSTDERR.destroy() ; fSTDERR.dealloc(2)
		}
		
		Foundation.pipe(fSTDIN)
		Foundation.pipe(fSTDOUT)
		Foundation.pipe(fSTDERR)
		
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
		let spawnRes = Foundation.posix_spawnp(&procPid, cmd, &action, UnsafeMutablePointer<posix_spawnattr_t>(()), cArgs, cEnv)
		posix_spawn_file_actions_destroy(&action)
		
		idx = 0
		for (; idx < cArgsCount; ++idx) {
			free(cArgs[idx])
		}
		
		idx = 0
		for (; idx < cEnvCount; ++idx) {
			free(cEnv[idx])
		}
		
		Foundation.close(fSTDIN[0])
		Foundation.close(fSTDOUT[1])
		Foundation.close(fSTDERR[1])
		if spawnRes != 0 {
			Foundation.close(fSTDIN[1])
			Foundation.close(fSTDOUT[0])
			Foundation.close(fSTDERR[0])
			try ThrowSystemError()
		}
		
		self.pid = procPid
		self.stdin = File(fd: fSTDIN[1], path: "")
		self.stdout = File(fd: fSTDOUT[0], path: "")
		self.stderr = File(fd: fSTDERR[0], path: "")
	}
	
	public func isOpen() -> Bool {
		return self.pid != -1
	}
	
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
	
	public func wait(hang: Bool = true) throws -> Int32 {
		var code = Int32(0)
		let status = Foundation.waitpid(self.pid, &code, WUNTRACED | (hang ? 0 : WNOHANG))
		if status == -1 {
			try ThrowSystemError()
		}
		self.pid = -1
		close()
		return code
	}
	
	public func kill(signal: Int32 = SIGTERM) throws -> Int32 {
		let status = Foundation.kill(self.pid, signal)
		guard status != -1 else {
			try ThrowSystemError()
		}
		return try self.wait()
	}
}




