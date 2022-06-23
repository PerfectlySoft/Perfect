//
//  CURLResponseInfos.swift
//  PerfectCURL
//
//  Created by Kyle Jessup on 2017-05-18.
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

import cURL

public protocol CURLResponseInfo {
	associatedtype ValueType
	func get(_ from: CURLResponse) -> ValueType?
}

extension CURLResponse.Info.StringValue: CURLResponseInfo {
	public typealias ValueType = String
	private var infoValue: CURLINFO {
		switch self {
		case .url: return CURLINFO_EFFECTIVE_URL
		case .ftpEntryPath: return CURLINFO_FTP_ENTRY_PATH
		case .redirectURL: return CURLINFO_REDIRECT_URL
		case .localIP: return CURLINFO_LOCAL_IP
		case .primaryIP: return CURLINFO_PRIMARY_IP
		case .contentType: return CURLINFO_CONTENT_TYPE
		}
	}

	public func get(_ from: CURLResponse) -> String? {
		let (i, code): (String, CURLcode) = from.curl.getInfo(infoValue)
		guard code == CURLE_OK else {
			return nil
		}
		return i
	}
}

extension CURLResponse.Info.IntValue: CURLResponseInfo {
	public typealias ValueType = Int
	private var infoValue: CURLINFO {
		switch self {
		case .responseCode: return CURLINFO_RESPONSE_CODE
		case .headerSize: return CURLINFO_HEADER_SIZE
		case .requestSize: return CURLINFO_REQUEST_SIZE
		case .sslVerifyResult: return CURLINFO_SSL_VERIFYRESULT
		case .fileTime: return CURLINFO_FILETIME
		case .redirectCount: return CURLINFO_REDIRECT_COUNT
		case .httpConnectCode: return CURLINFO_HTTP_CONNECTCODE
		case .httpAuthAvail: return CURLINFO_HTTPAUTH_AVAIL
		case .proxyAuthAvail: return CURLINFO_PROXYAUTH_AVAIL
		case .osErrno: return CURLINFO_OS_ERRNO
		case .numConnects: return CURLINFO_NUM_CONNECTS
		case .conditionUnmet: return CURLINFO_CONDITION_UNMET
		case .primaryPort: return CURLINFO_PRIMARY_PORT
		case .localPort: return CURLINFO_LOCAL_PORT
//		case .httpVersion: return CURLINFO_HTTP_VERSION
		}
	}

	public func get(_ from: CURLResponse) -> Int? {
		let (i, code): (Int, CURLcode) = from.curl.getInfo(infoValue)
		guard code == CURLE_OK else {
			return nil
		}
		return i
	}
}

extension CURLResponse.Info.DoubleValue: CURLResponseInfo {
	public typealias ValueType = Double
	private var infoValue: CURLINFO {
		switch self {
		case .totalTime: return CURLINFO_TOTAL_TIME
		case .nameLookupTime: return CURLINFO_NAMELOOKUP_TIME
		case .connectTime: return CURLINFO_CONNECT_TIME
		case .preTransferTime: return CURLINFO_PRETRANSFER_TIME
		case .sizeUpload: return CURLINFO_SIZE_UPLOAD
		case .sizeDownload: return CURLINFO_SIZE_DOWNLOAD
		case .speedDownload: return CURLINFO_SPEED_DOWNLOAD
		case .speedUpload: return CURLINFO_SPEED_UPLOAD
		case .contentLengthDownload: return CURLINFO_CONTENT_LENGTH_DOWNLOAD
		case .contentLengthUpload: return CURLINFO_CONTENT_LENGTH_UPLOAD
		case .startTransferTime: return CURLINFO_STARTTRANSFER_TIME
		case .redirectTime: return CURLINFO_REDIRECT_TIME
		case .appConnectTime: return CURLINFO_APPCONNECT_TIME
		}
	}

	public func get(_ from: CURLResponse) -> Double? {
		let (d, code): (Double, CURLcode) = from.curl.getInfo(infoValue)
		guard code == CURLE_OK else {
			return nil
		}
		return d
	}
}
