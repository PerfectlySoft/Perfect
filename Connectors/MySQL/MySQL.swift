//
//  MySQL.swift
//  MySQL
//
//  Created by Kyle Jessup on 2015-10-01.
//  Copyright © 2015 TreeFrog. All rights reserved.
//

import libmysqlclient

public class MySQL {
	var ptr: COpaquePointer
	
	
}

public class MySQLStmt {
	var ptr: COpaquePointer
	
	init(_ ptr: COpaquePointer) {
		self.ptr = ptr
	}
	
	deinit {
		self.close()
	}
	
	public func close() {
		
	}
	
}
