//
//  LogManager.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/21/15.
//
//

import Foundation

public class LogManager {
	
	static func logMessage(msg: String) {
		print(msg)
	}
	
	static func logMessageCode(msg: String, code: Int) {
		print("\(msg) \(code)")
	}
	
}