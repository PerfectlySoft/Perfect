//
//  MongoCursor.swift
//  MongoDB
//
//  Created by Kyle Jessup on 2015-11-19.
//  Copyright © 2015 PerfectlySoft. All rights reserved.
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

import libmongoc

public class MongoCursor {

	var ptr: COpaquePointer

	init(rawPtr: COpaquePointer) {
		self.ptr = rawPtr
	}
    
    deinit {
        close()
    }

	public func close() {
		if self.ptr != nil {
			mongoc_cursor_destroy(self.ptr)
			self.ptr = nil
		}
	}

	public func next() -> BSON? {
		var bson = UnsafePointer<bson_t>()
		if mongoc_cursor_next(self.ptr, &bson) {
			return NoDestroyBSON(rawBson: UnsafeMutablePointer<bson_t>(bson))
		}
		return nil
	}
}
