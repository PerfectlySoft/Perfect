//
//  PClose.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/5/15.
//
//

import Foundation

public protocol Closeable {
	
	func close()
	func doWithClose(c: ()->())
	
}

extension Closeable {
	public func doWithClose(c: ()->()) {
		defer { self.close() }
		
		c()
	}
}