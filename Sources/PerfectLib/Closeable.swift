//
//  PClose.swift
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

public protocol Closeable {
	
	func close()
	func doWithClose(c: ()->())
	
}

extension Closeable {
	public func doWithClose(c: ()->()) {
		defer { self.close() }
		
		c()
	}
}