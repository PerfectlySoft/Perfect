//
//  PerfectCRUDCoding.swift
//  PerfectCRUD
//
//  Created by Kyle Jessup on 2017-11-22.
//	Copyright (C) 2017 PerfectlySoft, Inc.
//
// ===----------------------------------------------------------------------===//
//
// This source file is part of the Perfect.org open source project
//
// Copyright (c) 2015 - 2017 PerfectlySoft Inc. and the Perfect project authors
// Licensed under Apache License v2.0
//
// See http://perfect.org/licensing.html for license information
//
// ===----------------------------------------------------------------------===//
//

import Foundation

public struct CRUDDecoderError: Error {
	public let msg: String
	public init(_ m: String) {
		msg = m
		CRUDLogging.log(.error, m)
	}
}

public struct CRUDEncoderError: Error {
	public let msg: String
	public init(_ m: String) {
		msg = m
		CRUDLogging.log(.error, m)
	}
}

public struct ColumnKey: CodingKey {
	public var stringValue: String
	public var intValue: Int? = nil
	public init?(stringValue s: String) {
		stringValue = s
	}
	public init?(intValue: Int) {
		return nil
	}
}

public indirect enum SpecialType {
	case uint8Array, int8Array, data, uuid, date, codable, url, wrapped
	public init?(_ type: Any.Type) {
		switch type {
		case is WrappedCodableProvider.Type:
			self = .wrapped
		case is [Int8].Type:
			self = .int8Array
		case is [UInt8].Type:
			self = .uint8Array
		case is Data.Type:
			self = .data
		case is UUID.Type:
			self = .uuid
		case is Date.Type:
			self = .date
		case is URL.Type:
			self = .url
		case is Codable.Type:
			self = .codable
		default:
			return nil
		}
	}
}
