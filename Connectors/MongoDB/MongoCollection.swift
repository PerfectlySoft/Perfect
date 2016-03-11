//
//  MongoCollection.swift
//  MongoDB
//
//  Created by Kyle Jessup on 2015-11-19.
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

public enum MongoInsertFlag: Int {
	case None
	case ContinueOnError
	case NoValidate

	private var mongoFlag: mongoc_insert_flags_t {
		switch self {
		case .None:
			return MONGOC_INSERT_NONE
		case .ContinueOnError:
			return MONGOC_INSERT_CONTINUE_ON_ERROR
		case .NoValidate:
			return mongoc_insert_flags_t(rawValue: MONGOC_INSERT_NO_VALIDATE)
		}
	}
}

public enum MongoUpdateFlag: Int {
	case None
	case Upsert
	case MultiUpdate
	case NoValidate

	private var mongoFlag: mongoc_update_flags_t {
		switch self {
		case .None:
			return MONGOC_UPDATE_NONE
		case .Upsert:
			return MONGOC_UPDATE_UPSERT
		case .MultiUpdate:
			return MONGOC_UPDATE_MULTI_UPDATE
		case .NoValidate:
			return mongoc_update_flags_t(rawValue: MONGOC_UPDATE_NO_VALIDATE)
		}
	}
}

public struct MongoQueryFlag: OptionSetType {
	public let rawValue: Int

	var queryFlags: mongoc_query_flags_t {
		return mongoc_query_flags_t(UInt32(self.rawValue))
	}

	public init(rawValue: Int) {
		self.rawValue = rawValue
	}

	private init(_ queryFlag: mongoc_query_flags_t) {
		self.init(rawValue: Int(queryFlag.rawValue))
	}

	static let None				= MongoQueryFlag(MONGOC_QUERY_NONE)
	static let TailableCursor	= MongoQueryFlag(MONGOC_QUERY_TAILABLE_CURSOR)
	static let SlaveOk			= MongoQueryFlag(MONGOC_QUERY_SLAVE_OK)
	static let OpLogReplay		= MongoQueryFlag(MONGOC_QUERY_OPLOG_REPLAY)
	static let NoCursorTimeout	= MongoQueryFlag(MONGOC_QUERY_NO_CURSOR_TIMEOUT)
	static let AwaitData		= MongoQueryFlag(MONGOC_QUERY_AWAIT_DATA)
	static let Exhaust			= MongoQueryFlag(MONGOC_QUERY_EXHAUST)
	static let Partial			= MongoQueryFlag(MONGOC_QUERY_PARTIAL)
}

public enum MongoRemoveFlag: Int {
	case None
	case SingleRemove

	private var mongoFlag: mongoc_remove_flags_t {
		switch self {
		case .None:
			return MONGOC_REMOVE_NONE
		case .SingleRemove:
			return MONGOC_REMOVE_SINGLE_REMOVE
		}
	}
}

public class MongoIndexOptionsGeo {
	var rawOpt = UnsafeMutablePointer<mongoc_index_opt_geo_t>.alloc(1)

	public init(twodSphereVersion: UInt8? = nil, twodBitsPrecision: UInt8? = nil, twodLocationMin: Double? = nil, twodLocationMax: Double? = nil, haystackBucketSize: Double? = nil) {
		mongoc_index_opt_geo_init(self.rawOpt)
		if let twodSphereVersion = twodSphereVersion {
			self.rawOpt.memory.twod_sphere_version = twodSphereVersion
		}
		if let twodBitsPrecision = twodBitsPrecision {
			self.rawOpt.memory.twod_bits_precision = twodBitsPrecision
		}
		if let twodLocationMin = twodLocationMin {
			self.rawOpt.memory.twod_location_min = twodLocationMin
		}
		if let twodLocationMax = twodLocationMax {
			self.rawOpt.memory.twod_location_max = twodLocationMax
		}
		if let haystackBucketSize = haystackBucketSize {
			self.rawOpt.memory.haystack_bucket_size = haystackBucketSize
		}
	}

	deinit {
		self.rawOpt.destroy(1)
		self.rawOpt.dealloc(1)
	}
}

public class MongoIndexOptions {

	var rawOpt = mongoc_index_opt_t()

	// who knows what the default options are.
	// guard against the case where these values were set to something in the defaults.
	// we don't want to free a pointer which isn't ours
	var nameNil: Bool, defLangNil: Bool, langOverNil: Bool
	var weightsDoc: BSON?
	var geoOptions: MongoIndexOptionsGeo?
	var storageOptions: UnsafeMutablePointer<mongoc_index_opt_storage_t>?

	public init(name: String? = nil, background: Bool? = nil, unique: Bool? = nil, dropDups: Bool? = nil, sparse: Bool? = nil,
				expireAfterSeconds: Int32? = nil, v: Int32? = nil, defaultLanguage: String? = nil, languageOverride: String? = nil,
		weights: BSON? = nil, geoOptions: MongoIndexOptionsGeo? = nil, storageOptions: MongoIndexStorageOptionType? = nil) {
		mongoc_index_opt_init(&self.rawOpt)

		self.nameNil = self.rawOpt.name == nil
		self.defLangNil = self.rawOpt.default_language == nil
		self.langOverNil = self.rawOpt.language_override == nil

		if let name = name {
			self.nameNil = true
			self.rawOpt.name = UnsafePointer<Int8>(strdup(name))
		}
		if let background = background {
			self.rawOpt.background = background
		}
		if let unique = unique {
			self.rawOpt.unique = unique
		}
		if let dropDups = dropDups {
			self.rawOpt.drop_dups = dropDups
		}
		if let sparse = sparse {
			self.rawOpt.sparse = sparse
		}
		if let expireAfterSeconds = expireAfterSeconds {
			self.rawOpt.expire_after_seconds = expireAfterSeconds
		}
		if let v = v {
			self.rawOpt.v = v
		}
		if let defaultLanguage = defaultLanguage {
			self.defLangNil = true
			self.rawOpt.default_language = UnsafePointer<Int8>(strdup(defaultLanguage))
		}
		if let languageOverride = languageOverride {
			self.langOverNil = true
			self.rawOpt.language_override = UnsafePointer<Int8>(strdup(languageOverride))
		}
		if let weights = weights {
			self.weightsDoc = weights // reference this so the ptr doesn't disappear beneath us
			self.rawOpt.weights = UnsafePointer<bson_t>(weights.doc)
		}
		if let geoOptions = geoOptions {
			self.geoOptions = geoOptions
			self.rawOpt.geo_options = geoOptions.rawOpt
		}
		if let storageOptions = storageOptions {
			self.storageOptions = UnsafeMutablePointer<mongoc_index_opt_storage_t>.alloc(1)
			self.storageOptions!.memory.type = Int32(storageOptions.rawValue)
		}
	}

	deinit {
		if self.nameNil && self.rawOpt.name != nil {
			free(UnsafeMutablePointer<()>(self.rawOpt.name))
		}
		if self.defLangNil && self.rawOpt.default_language != nil {
			free(UnsafeMutablePointer<()>(self.rawOpt.default_language))
		}
		if self.langOverNil && self.rawOpt.language_override != nil {
			free(UnsafeMutablePointer<()>(self.rawOpt.language_override))
		}
		if self.storageOptions != nil {
			self.storageOptions!.dealloc(1)
		}
	}
}

public enum MongoIndexStorageOptionType: UInt32 {
	case MMapV1, WiredTiger

	var mongoType: UInt32 {
		switch self {
		case .MMapV1:
			return MONGOC_INDEX_STORAGE_OPT_MMAPV1.rawValue
		case .WiredTiger:
			return MONGOC_INDEX_STORAGE_OPT_WIREDTIGER.rawValue
		}
	}
}

public class MongoCollection {

	var ptr: COpaquePointer

	public typealias Result = MongoResult

	public init(client: MongoClient, databaseName: String, collectionName: String) {
		self.ptr = mongoc_client_get_collection(client.ptr, databaseName, collectionName)
	}

	init(rawPtr: COpaquePointer) {
		self.ptr = rawPtr
	}
    
    deinit {
        close()
    }

	public func close() {
		if self.ptr != nil {
			mongoc_collection_destroy(self.ptr)
			self.ptr = nil
		}
	}

	public func insert(document: BSON, flag: MongoInsertFlag = .None) -> Result {
		var error = bson_error_t()
		let res = mongoc_collection_insert(self.ptr, flag.mongoFlag, document.doc, nil, &error)
		guard res == true else {
			return Result.fromError(error)
		}
		return .Success
	}

	public func update(update: BSON, selector: BSON, flag: MongoUpdateFlag = .None) -> Result {
		var error = bson_error_t()
		let res = mongoc_collection_update(self.ptr, flag.mongoFlag, selector.doc, update.doc, nil, &error)
		guard res == true else {
			return Result.fromError(error)
		}
		return .Success
	}

	public func remove(selector: BSON, flag: MongoRemoveFlag = .None) -> Result {
		var error = bson_error_t()
		let res = mongoc_collection_remove(self.ptr, flag.mongoFlag, selector.doc, nil, &error)
		guard res == true else {
			return Result.fromError(error)
		}
		return .Success
	}

	public func save(document: BSON) -> Result {
		var error = bson_error_t()
		let res = mongoc_collection_save(self.ptr, document.doc, nil, &error)
		guard res == true else {
			return Result.fromError(error)
		}
		return .Success
	}

	public func rename(newDbName: String, newCollectionName: String, dropExisting: Bool) -> Result {
		var error = bson_error_t()
		let res = mongoc_collection_rename(self.ptr, newDbName, newCollectionName, dropExisting, &error)
		guard res == true else {
			return Result.fromError(error)
		}
		return .Success
	}

	public func name() -> String {
		return String.fromCString(mongoc_collection_get_name(self.ptr))!
	}

	public func validate(options: BSON) -> Result {
		var error = bson_error_t()
		let reply = BSON()
		let res = mongoc_collection_validate(self.ptr, options.doc, reply.doc, &error)
		guard res == true else {
			return Result.fromError(error)
		}
		return .ReplyDoc(reply)
	}

	public func stats(options: BSON) -> Result {
		var error = bson_error_t()
		let reply = BSON()
		let res = mongoc_collection_stats(self.ptr, options.doc, reply.doc, &error)
		guard res == true else {
			return Result.fromError(error)
		}
		return .ReplyDoc(reply)
	}

	public func find(query: BSON, fields: BSON? = nil, flags: MongoQueryFlag = MongoQueryFlag.None, skip: Int = 0, limit: Int = 0, batchSize: Int = 0) -> MongoCursor? {
		let cursor = mongoc_collection_find(self.ptr, flags.queryFlags, UInt32(skip), UInt32(limit), UInt32(batchSize), query.doc, fields == nil ? nil : fields!.doc, nil)
		guard cursor != nil else {
			return nil
		}
		return MongoCursor(rawPtr: cursor)
	}

	public func createIndex(keys: BSON, options: MongoIndexOptions) -> Result {
		var error = bson_error_t()
		let res = mongoc_collection_create_index(self.ptr, keys.doc, &options.rawOpt, &error)
		guard res == true else {
			return Result.fromError(error)
		}
		return .Success
	}

	public func dropIndex(name: String) -> Result {
		var error = bson_error_t()
		let res = mongoc_collection_drop_index(self.ptr, name, &error)
		guard res == true else {
			return Result.fromError(error)
		}
		return .Success
	}

	public func drop() -> Result {
		var error = bson_error_t()
		let res = mongoc_collection_drop(self.ptr, &error)
		guard res == true else {
			return Result.fromError(error)
		}
		return .Success
	}

	public func count(query: BSON, fields: BSON? = nil, flags: MongoQueryFlag = MongoQueryFlag.None, skip: Int = 0, limit: Int = 0, batchSize: Int = 0) -> Result {
		var error = bson_error_t()
		let ires = mongoc_collection_count(self.ptr, flags.queryFlags, query.doc, Int64(skip), Int64(limit), nil, &error)
		guard ires != -1 else {
			return Result.fromError(error)
		}
		return .ReplyInt(Int(ires))
	}

	public func findAndModify(query: BSON, sort: BSON, update: BSON, fields: BSON, remove: Bool, upsert: Bool, new: Bool) -> Result {
		var error = bson_error_t()
		let reply = BSON()
		let res = mongoc_collection_find_and_modify(self.ptr, query.doc, sort.doc, update.doc, fields.doc, remove, upsert, new, reply.doc, &error)
		guard res == true else {
			return Result.fromError(error)
		}
		return .ReplyDoc(reply)
	}

	public func getLastError() -> BSON {
		let reply = mongoc_collection_get_last_error(self.ptr)
		return NoDestroyBSON(rawBson: UnsafeMutablePointer(reply))
	}

}
