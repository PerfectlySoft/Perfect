//
//  XCTestManifests.swift
//
//  Created by Kyle Jessup on 2015-10-19.
//  Copyright © 2015 PerfectlySoft. All rights reserved.
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

import XCTest

#if !os(OSX)
public func allTests() -> [XCTestCaseEntry] {
	return [
			testCase(PerfectLibTests.allTests)
	]
}
#endif
