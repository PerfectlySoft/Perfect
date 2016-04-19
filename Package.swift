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
	targets: [
		Target(name: "PerfectLib", dependencies: [
										.Target(name: "OpenSSL"),
										.Target(name: "ICU"),
										.Target(name: "cURL"),
										.Target(name: "LinuxBridge")]),
		Target(name: "OpenSSL"),
		Target(name: "ICU"),
		Target(name: "cURL"),
		Target(name: "LinuxBridge")
		],
	exclude: ["Sources/PerfectLibTests"]
)
#else
let package = Package(
	name: "PerfectLib",
	targets: [
		Target(name: "PerfectLib", dependencies: [
										.Target(name: "OpenSSL"),
										.Target(name: "ICU"),
										.Target(name: "cURL")]),
		Target(name: "OpenSSL"),
		Target(name: "ICU"),
		Target(name: "cURL"),
		Target(name: "PerfectLibTests", dependencies: [.Target(name: "PerfectLib")])
		],
	exclude: ["Sources/LinuxBridge"]
)
#endif
