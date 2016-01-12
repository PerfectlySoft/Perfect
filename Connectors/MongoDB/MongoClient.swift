//
//  MongoClient.swift
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

public enum MongoResult {
	case Success
	case Error(UInt32, UInt32, String)
	case ReplyDoc(BSON)
	case ReplyInt(Int)
	case ReplyCollection(MongoCollection)

	static func fromError(error: bson_error_t) -> MongoResult {
		var vError = error
		let message = withUnsafePointer(&vError.message) {
			String.fromCString(UnsafePointer($0))!
		}
		return .Error(error.domain, error.code, message)
	}
}

public class MongoClient {

	var ptr: COpaquePointer

	public typealias Result = MongoResult

	public init(uri: String) {
		self.ptr = mongoc_client_new(uri)
	}

	public func close() {
		if self.ptr != nil {
			mongoc_client_destroy(self.ptr)
			self.ptr = nil
		}
	}

	public func getCollection(databaseName: String, collectionName: String) -> MongoCollection {
		return MongoCollection(client: self, databaseName: databaseName, collectionName: collectionName)
	}

	public func getDatabase(databaseName: String) -> MongoDatabase {
		return MongoDatabase(client: self, databaseName: databaseName)
	}

	public func serverStatus() -> Result {
		var error = bson_error_t()
		let readPrefs = mongoc_read_prefs_new(MONGOC_READ_PRIMARY)
		defer {
			mongoc_read_prefs_destroy(readPrefs)
		}
		let bson = BSON()
		guard mongoc_client_get_server_status(self.ptr, readPrefs, bson.doc, &error) else {
			return Result.fromError(error)
		}
		return .ReplyDoc(bson)
	}

	public func databaseNames() -> [String] {
		let names = mongoc_client_get_database_names(self.ptr, nil)
		var ret = [String]()
		if names != nil {
			var curr = names
			while curr[0] != nil {
				ret.append(String.fromCString(curr.memory)!)
				curr = curr.successor()
			}
			bson_strfreev(names)
		}
		return ret
	}

}
