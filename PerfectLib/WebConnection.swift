//
//  WebConnection.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/6/15.
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

/// This protocol represents a generalized web server connection.
public protocol WebConnection {
	/// The TCP based connection
	var connection: NetTCP { get }
	/// The parameters sent by the client
	var requestParams: [String:String] { get set }
	/// Any non mime based request body data
	var stdin: [UInt8]? { get }
	/// Parsed mime based body data
	var mimes: MimeReader? { get }
	
	/// Set the response status code and message. For example, 200, "OK".
	func setStatus(code: Int, msg: String)
	/// Get the response status code and message.
	func getStatus() -> (Int, String)
	/// Add a response header which will be sent to the client.
	func writeHeaderLine(h: String)
	/// Send header bytes to the client.
	func writeHeaderBytes(b: [UInt8])
	/// Write body bytes to the client. Any pending header data will be written first.
	func writeBodyBytes(b: [UInt8])
	
}
