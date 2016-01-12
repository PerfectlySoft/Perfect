//
//  MongoDatabase.swift
//  MongoDB
//
//  Created by Kyle Jessup on 2015-11-20.
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

public class MongoDatabase {

	var ptr: COpaquePointer

	public typealias Result = MongoResult

	public init(client: MongoClient, databaseName: String) {
		self.ptr = mongoc_client_get_database(client.ptr, databaseName)
	}

	public func close() {
		if self.ptr != nil {
			mongoc_database_destroy(self.ptr)
			self.ptr = nil
		}
	}

	public func drop() -> Result {
		var error = bson_error_t()
		if mongoc_database_drop(self.ptr, &error) {
			return .Success
		}
		return Result.fromError(error)
	}

	public func name() -> String {
		return String.fromCString(mongoc_database_get_name(self.ptr))!
	}

	public func createCollection(collectionName: String, options: BSON) -> Result {
		var error = bson_error_t()
		let col = mongoc_database_create_collection(self.ptr, collectionName, options.doc, &error)
		guard col != nil else {
			return Result.fromError(error)
		}
		return .ReplyCollection(MongoCollection(rawPtr: col))
	}

	public func getCollection(collectionName: String) -> MongoCollection {
		let col = mongoc_database_get_collection(self.ptr, collectionName)
		return MongoCollection(rawPtr: col)
	}

	public func collectionNames() -> [String] {
		let names = mongoc_database_get_collection_names(self.ptr, nil)
		var ret = [String]()
		if names != nil {
			var curr = names
			while curr.memory != nil {
				ret.append(String.fromCString(curr.memory)!)
				curr = curr.successor()
			}
			bson_strfreev(names)
		}
		return ret
	}


}
