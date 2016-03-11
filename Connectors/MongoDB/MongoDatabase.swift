//
//  MongoDatabase.swift
//  MongoDB
//
//  Created by Kyle Jessup on 2015-11-20.
//  Copyright © 2015 PerfectlySoft. All rights reserved.
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

import libmongoc

public class MongoDatabase {

	var ptr: COpaquePointer

	public typealias Result = MongoResult

	public init(client: MongoClient, databaseName: String) {
		self.ptr = mongoc_client_get_database(client.ptr, databaseName)
	}
    
    deinit {
        close()
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
