//
//  WebConnection.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/6/15.
//
//

import Foundation

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
