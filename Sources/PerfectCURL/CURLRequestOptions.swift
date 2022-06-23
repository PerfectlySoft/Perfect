//
//  CURLRequestOptions.swift
//  PerfectCURL
//
//  Created by Kyle Jessup on 2017-05-17.
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
import PerfectLib
#if os(Linux)
import Glibc
#else
import Darwin
#endif

extension CURLRequest.Option {

	private func headerAdd(_ curl: CURL, optName: CURLRequest.Header.Name, optValue: String) {
		if optValue.isEmpty {
			curl.setOption(CURLOPT_HTTPHEADER, s: "\(optName.standardName);")
		} else {
			curl.setOption(CURLOPT_HTTPHEADER, s: "\(optName.standardName): \(optValue)")
		}
	}
	// swiftlint:disable cyclomatic_complexity function_body_length
	func apply(to request: CURLRequest) {
		let curl = request.curl
		switch self {
		case .url(let optString):
			curl.setOption(CURLOPT_URL, s: optString)
		case .port(let optInt):
			curl.setOption(CURLOPT_PORT, int: optInt)
		case .failOnError:
			curl.setOption(CURLOPT_FAILONERROR, int: 1)
		case .userPwd(let optString):
			curl.setOption(CURLOPT_USERPWD, s: optString)
		case .proxy(let optString):
			curl.setOption(CURLOPT_PROXY, s: optString)
		case .proxyUserPwd(let optString):
			curl.setOption(CURLOPT_PROXYUSERPWD, s: optString)
		case .proxyPort(let optInt):
			curl.setOption(CURLOPT_PROXYPORT, int: optInt)
		case .timeout(let optInt):
			curl.setOption(CURLOPT_TIMEOUT, int: optInt)
		case .connectTimeout(let optInt):
			curl.setOption(CURLOPT_CONNECTTIMEOUT, int: optInt)
		case .lowSpeedLimit(let optInt):
			curl.setOption(CURLOPT_LOW_SPEED_LIMIT, int: optInt)
		case .lowSpeedTime(let optInt):
			curl.setOption(CURLOPT_LOW_SPEED_TIME, int: optInt)
		case .range(let optString):
			curl.setOption(CURLOPT_RANGE, s: optString)
		case .resumeFrom(let optInt):
			curl.setOption(CURLOPT_RESUME_FROM_LARGE, int: Int64(optInt))
		case .cookie(let optString):
			curl.setOption(CURLOPT_COOKIE, s: optString)
		case .cookieFile(let optString):
			curl.setOption(CURLOPT_COOKIEFILE, s: optString)
		case .cookieJar(let optString):
			curl.setOption(CURLOPT_COOKIEJAR, s: optString)
		case .followLocation(let optBool):
			curl.setOption(CURLOPT_FOLLOWLOCATION, int: optBool ? 1 : 0)
		case .maxRedirects(let optInt):
			curl.setOption(CURLOPT_MAXREDIRS, int: optInt)
		case .maxConnects(let optInt):
			curl.setOption(CURLOPT_MAXCONNECTS, int: optInt)
		case .autoReferer(let optBool):
			curl.setOption(CURLOPT_AUTOREFERER, int: optBool ? 1 : 0)
		case .krbLevel(let optString):
			curl.setOption(CURLOPT_KRBLEVEL, s: optString.description)
		case .addHeader(let optName, let optValue):
			headerAdd(curl, optName: optName, optValue: optValue)
		case .addHeaders(let optArray):
			optArray.forEach { self.headerAdd(curl, optName: $0, optValue: $1) }
		case .replaceHeader(let optName, let optValue):
			curl.setOption(CURLOPT_HTTPHEADER, s: "\(optName.standardName):")
			headerAdd(curl, optName: optName, optValue: optValue)
		case .removeHeader(let optName):
			curl.setOption(CURLOPT_HTTPHEADER, s: "\(optName.standardName):")
		case .useSSL:
			curl.setOption(CURLOPT_USE_SSL, int: Int(CURLUSESSL_ALL.rawValue))
		case .sslCert(let optString):
			curl.setOption(CURLOPT_SSLCERT, s: optString)
		case .sslCertType(let optString):
			curl.setOption(CURLOPT_SSLCERTTYPE, s: optString.description)
		case .sslKey(let optString):
			curl.setOption(CURLOPT_SSLKEY, s: optString)
		case .sslKeyPwd(let optString):
			curl.setOption(CURLOPT_KEYPASSWD, s: optString)
		case .sslKeyType(let optString):
			curl.setOption(CURLOPT_SSLKEYTYPE, s: optString.description)
		case .sslVersion(let optVersion):
			let value: Int
			switch optVersion {
			case .tlsV1: value = CURL_SSLVERSION_TLSv1
			case .tlsV1_1: value = CURL_SSLVERSION_TLSv1_1
			case .tlsV1_2: value = CURL_SSLVERSION_TLSv1_2
			}
			curl.setOption(CURLOPT_SSLVERSION, int: value)
		case .sslVerifyPeer(let optBool):
			curl.setOption(CURLOPT_SSL_VERIFYPEER, int: optBool ? 1 : 0)
		case .sslVerifyHost(let optBool):
			curl.setOption(CURLOPT_SSL_VERIFYHOST, int: optBool ? 2 : 0)
		case .sslCAFilePath(let optString):
			curl.setOption(CURLOPT_CAINFO, s: optString)
		case .sslCADirPath(let optString):
			curl.setOption(CURLOPT_CAPATH, s: optString)
		case .sslPinnedPublicKey(let optString):
			curl.setOption(CURLOPT_PINNEDPUBLICKEY, s: optString)
		case .sslCiphers(let optArray):
			curl.setOption(CURLOPT_SSL_CIPHER_LIST, s: optArray.joined(separator: ":"))
		case .ftpPreCommands(let optArray):
			optArray.forEach { curl.setOption(CURLOPT_PREQUOTE, s: $0) }
		case .ftpPostCommands(let optArray):
			optArray.forEach { curl.setOption(CURLOPT_POSTQUOTE, s: $0) }
		case .ftpPort(let optString):
			curl.setOption(CURLOPT_FTPPORT, s: optString)
		case .ftpResponseTimeout(let optInt):
			curl.setOption(CURLOPT_FTP_RESPONSE_TIMEOUT, int: optInt)
		case .sshPublicKey(let optString):
			curl.setOption(CURLOPT_SSH_PUBLIC_KEYFILE, s: optString)
		case .sshPrivateKey(let optString):
			curl.setOption(CURLOPT_SSH_PRIVATE_KEYFILE, s: optString)
		case .httpMethod(let optHTTPMethod):
			switch optHTTPMethod {
			case .get: curl.setOption(CURLOPT_HTTPGET, int: 1)
			case .post: curl.setOption(CURLOPT_POST, int: 1)
			case .head: curl.setOption(CURLOPT_NOBODY, int: 1)
			case .patch: curl.setOption(CURLOPT_CUSTOMREQUEST, s: "PATCH")
			case .delete,
			     .put,
			     .trace,
			     .options,
			     .connect,
			     .custom(_): curl.setOption(CURLOPT_CUSTOMREQUEST, s: optHTTPMethod.description)
			}
		case .postField(let optPOSTField):
			if nil == request.postFields {
				request.postFields = CURLRequest.POSTFields()
			}
			switch optPOSTField.type {
			case .value:
				_ = request.postFields?.append(key: optPOSTField.name, value: optPOSTField.value, mimeType: optPOSTField.mimeType ?? "")
			case .file:
				_ = request.postFields?.append(key: optPOSTField.name, path: optPOSTField.value, mimeType: optPOSTField.mimeType ?? "")
			}
		case .postData(let optBytes):
			curl.setOption(CURLOPT_POSTFIELDSIZE_LARGE, int: optBytes.count)
			curl.setOption(CURLOPT_COPYPOSTFIELDS, v: optBytes)
		case .postString(let optString):
			let bytes = Array(optString.utf8)
			curl.setOption(CURLOPT_POSTFIELDSIZE_LARGE, int: bytes.count)
			curl.setOption(CURLOPT_COPYPOSTFIELDS, v: bytes)
		case .mailFrom(let optString):
			curl.setOption(CURLOPT_MAIL_FROM, s: optString)
		case .mailRcpt(let optString):
			curl.setOption(CURLOPT_MAIL_RCPT, s: optString)
		case .verbose:
			curl.setOption(CURLOPT_VERBOSE, int: 1)
		case .header:
			curl.setOption(CURLOPT_HEADER, int: 1)
		case .upload(let gen):
			curl.setOption(CURLOPT_UPLOAD, int: 1)
			request.uploadBodyGen = gen
			if let len = gen.contentLength {
				curl.setOption(CURLOPT_INFILESIZE_LARGE, int: len)
			}
			let opaqueRequest = Unmanaged<AnyObject>.passRetained(request as AnyObject).toOpaque()
			let curlFunc: curl_func = { ptr, size, count, opaque -> Int in
				guard let opaque = opaque,
					let ptr = ptr else {
					return 0
				}
				let this = Unmanaged<CURLRequest>.fromOpaque(opaque).takeUnretainedValue()
				guard let bytes = this.uploadBodyGen?.next(byteCount: size*count) else {
					return 0
				}
				memcpy(ptr, bytes, bytes.count)
				return bytes.count
			}
			curl.setOption(CURLOPT_READDATA, v: opaqueRequest)
			curl.setOption(CURLOPT_READFUNCTION, f: curlFunc)
		case .uploadFile(let path):
			return CURLRequest.Option.upload(FileUploader(File(path))).apply(to: request)
		case .acceptEncoding(let str):
			curl.setOption(CURLOPT_ACCEPT_ENCODING, s: str)
		}
	}
}
