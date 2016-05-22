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

#if os(Linux)
let package = Package(
	name: "PerfectLib",
	targets: [],
	dependencies: [
	              	.Package(url: "https://github.com/PerfectlySoft/Perfect-libcurl.git", majorVersion: 0, minor: 5),
	              	.Package(url: "https://github.com/PerfectlySoft/Perfect-OpenSSL-Linux.git", majorVersion: 0, minor: 2),
									.Package(url: "https://github.com/PerfectlySoft/Perfect-LinuxBridge.git", majorVersion: 0, minor: 3)
	],
	exclude: ["Sources/LinuxBridge", "Sources/OpenSSL", "Sources/cURL"]
)
#else
let package = Package(
	name: "PerfectLib",
	targets: [],
	dependencies: [
	              	.Package(url: "https://github.com/PerfectlySoft/Perfect-libcurl.git", majorVersion: 0, minor: 5),
	              	.Package(url: "https://github.com/PerfectlySoft/Perfect-OpenSSL.git", majorVersion: 0, minor: 3)
	],
	exclude: ["Sources/LinuxBridge", "Sources/OpenSSL", "Sources/cURL"]
)
#endif

products.append(Product(name: "PerfectLib", type: .Library(.Dynamic), modules: "PerfectLib"))

//print("\(package.toTOML())")
