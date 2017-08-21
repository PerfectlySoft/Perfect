//
//  Package.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 3/22/16.
//	Copyright (C) 2016 PerfectlySoft, Inc.
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

import PackageDescription

var dependencies = Array<Package.Dependency>()

#if os(Linux)
dependencies += [.Package(url: "https://github.com/PerfectlySoft/Perfect-LinuxBridge.git", majorVersion: 2)]
#else

#endif

let package = Package(
	name: "PerfectLib",
	targets: [],
	dependencies: dependencies,
	exclude: []
)
