//
//  WebConnection.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/6/15.
//
//

import Foundation

public protocol WebConnection {
	
	var connection: NetTCP { get }
	var requestParams: Dictionary<String, String> { get }
	var stdin: [UInt8]? { get }
	var mimes: MimeReader? { get }
	
	func setStatus(code: Int, msg: String)
	func getStatus() -> (Int, String)
	func writeHeaderLine(h: String)
	func writeHeaderBytes(b: [UInt8])
	func writeBodyBytes(b: [UInt8])
	
}
