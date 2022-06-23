//
//  PerfectCrypto.swift
//  PerfectCrypto
//
//  Created by Kyle Jessup on 2017-02-07.
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

public enum PerfectCrypto {
	public static var isInitialized: Bool = {
		return OpenSSLInternal.isInitialized
	}()
}

public struct CryptoError: Error {
	public let code: Int
	public let msg: String
}
