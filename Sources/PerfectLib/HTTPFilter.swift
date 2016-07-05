//
//  HTTPFilter.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2016-07-02.
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

/// Execution priority for request filters.
public enum HTTPFilterPriority {
	/// Lowest priority. Run last.
	case low
	/// Medium priority.
	case medium
	/// Highest priority. Run first.
	case high
}

/// Result from one filter.
public enum HTTPRequestFilterResult {
	/// Continue with filtering.
	case `continue`(HTTPRequest, HTTPResponse)
	/// Halt and finalize the request. Handler is not run.
	case halt(HTTPRequest, HTTPResponse)
	/// Stop filtering and execute the request.
	/// No other filters at the current priority level will be executed.
	case execute(HTTPRequest, HTTPResponse)
}

/// Response from one filter.
public enum HTTPResponseFilterResult {
	/// Continue with filtering.
	case `continue`
	/// Stop executing filters until the next push.
	case done
	/// Halt and close the request.
	case halt
}

/// A filter which can be called to modify a HTTPRequest.
public protocol HTTPRequestFilter {
	/// Called once after the request has been read but before any handler is executed.
	func filter(request: HTTPRequest, response: HTTPResponse, callback: (HTTPRequestFilterResult) -> ())
}

/// A filter which can be called to modify a HTTPResponse.
public protocol HTTPResponseFilter {
	/// Called once before headers are sent to the client.
	func filterHeaders(response: HTTPResponse, callback: (HTTPResponseFilterResult) -> ())
	/// Called zero or more times for each bit of body data which is sent to the client.
	func filterBody(response: HTTPResponse, callback: (HTTPResponseFilterResult) -> ())
}
