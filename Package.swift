// swift-tools-version:4.0
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

var urls: [String]?
var deps: [Target.Dependency]?

#if os(Linux)
urls = ["https://github.com/PerfectlySoft/Perfect-LinuxBridge.git"]
deps = ["LinuxBridge"]
#else

#endif

let package = Package(
	name: "PerfectLib",
  products: [
		.library(name: "PerfectLib", type: .`dynamic`, targets: ["PerfectLib"])
  ],
	dependencies: urls?.map { .package(url: $0, from: "3.0.0") } ?? [],
	targets: [
		.target(name: "PerfectLib", dependencies: deps ?? [], path: "Sources"),
  ],
  swiftLanguageVersions: [3]
)
