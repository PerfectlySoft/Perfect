//
//  WebConnection.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/6/15.
//	Copyright (C) 2015 PerfectlySoft, Inc.
//
//	This program is free software: you can redistribute it and/or modify
//	it under the terms of the GNU Affero General Public License as
//	published by the Free Software Foundation, either version 3 of the
//	License, or (at your option) any later version, as supplemented by the
//	Perfect Additional Terms.
//
//	This program is distributed in the hope that it will be useful,
//	but WITHOUT ANY WARRANTY; without even the implied warranty of
//	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//	GNU Affero General Public License, as supplemented by the
//	Perfect Additional Terms, for more details.
//
//	You should have received a copy of the GNU Affero General Public License
//	and the Perfect Additional Terms that immediately follow the terms and
//	conditions of the GNU Affero General Public License along with this
//	program. If not, see <http://www.perfect.org/AGPL_3_0_With_Perfect_Additional_Terms.txt>.
//

/// This protocol represents a generalized web server connection.
public protocol WebConnection {
	/// The TCP based connection
	var connection: NetTCP { get }
	/// The parameters sent by the client
	var requestParams: Dictionary<String, String> { get }
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
	/// Write body bytes ot the client. Any pending header data will be written first.
	func writeBodyBytes(b: [UInt8])
	
}
