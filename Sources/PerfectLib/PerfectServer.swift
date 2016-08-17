//
//  Perfect.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/5/15.
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
#else
    import Darwin
#endif

/// Provides access to various system level features for the process.
/// A static instance of this class is created at startup and all access to this object go through the `PerfectServer.staticPerfectServer` static property.
public struct PerfectServer {
	
	@available(*, deprecated, message: "No longer required to call this")
	public static func initializeServices() {
	
	}
	
    /// Switch the current process to run with the permissions of the indicated user
    public static func switchTo(userName unam: String) throws {
        guard let pw = getpwnam(unam) else {
            try ThrowSystemError()
        }
        let gid = pw.pointee.pw_gid
        let uid = pw.pointee.pw_uid
        guard 0 == setgid(gid) else {
            try ThrowSystemError()
        }
        guard 0 == setuid(uid) else {
            try ThrowSystemError()
        }
    }
}

