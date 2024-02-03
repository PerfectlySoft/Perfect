//
//  main.swift
//  PerfectTemplate
//
//  Created by Kyle Jessup on 2015-11-05.
//	Copyright (C) 2015 PerfectlySoft, Inc.
//
// ===----------------------------------------------------------------------===//
//
// This source file is part of the Perfect.org open source project
//
// Copyright (c) 2015 - 2016 PerfectlySoft Inc. and the Perfect project authors
// Licensed under Apache License v2.0
//
// See http://perfect.org/licensing.html for license information
//
// ===----------------------------------------------------------------------===//
//
import PerfectHTTP
import PerfectHTTPServer

let cfg = Settings.default

let routes = try Gateway.load()
try HTTPServer.launch(name: cfg.name, port: cfg.port, routes: routes,
                      requestFilters: Gateway.requestFitlers,
                      responseFilters: [(PerfectHTTPServer.HTTPFilter.contentCompression(data: [:]), HTTPFilterPriority.high)])
