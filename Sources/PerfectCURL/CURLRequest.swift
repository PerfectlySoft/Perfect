//
//  CURLRequest.swift
//  PerfectCURL
//
//  Created by Kyle Jessup on 2017-05-10.
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
import PerfectThread
import PerfectLib

public enum TLSMethod {
	case tlsV1
	case tlsV1_1
	case tlsV1_2
}

public protocol CURLRequestBodyGenerator {
	var contentLength: Int? { get }
	mutating func next(byteCount: Int) -> [UInt8]?
}

public struct FileUploader: CURLRequestBodyGenerator {
	let file: File
	public init(_ f: File) {
		file = f
	}
	public var contentLength: Int? {
		return file.size
	}
	public mutating func next(byteCount: Int) -> [UInt8]? {
		return try? file.readSomeBytes(count: byteCount)
	}
}

/// Creates and configures a CURL request.
/// init with a URL and zero or more options.
/// Call .perform to get the CURLResponse
open class CURLRequest {
	typealias POSTFields = CURL.POSTFields
	/// A header which can be added to the request.
	public typealias Header = HTTPRequestHeader
	/// A POST name/value field. Can indicate a file upload by giving a file path.
	public struct POSTField {
		enum FieldType { case value, file }
		let name: String
		let value: String
		let mimeType: String?
		let type: FieldType
		/// Init with a name, value and optional mime-type.
		public init(name: String, value: String, mimeType: String? = nil) {
			self.name = name
			self.value = value
			self.type = .value
			self.mimeType = mimeType
		}
		/// Init with a name, file path and optional mime-type.
		public init(name: String, filePath: String, mimeType: String? = nil) {
			self.name = name
			self.value = filePath
			self.type = .file
			self.mimeType = mimeType
		}
	}
	/// Kerberos security level for FTP requests. Used with `.kbrLevel` option.
	public enum KBRLevel {
		case clear, safe, confidential, `private`
		var description: String {
			switch self {
			case .clear: return "clear"
			case .safe: return "safe"
			case .confidential: return "confidential"
			case .private: return "private"
			}
		}
	}
	/// SSL certificate format. Used with `.sslCertType` option.
	/// The `.eng` case indicates that the `.sslCertType` value should be passed directly to the crypto engine (usually OpenSSL).
	public enum SSLFileType {
		case pem, der, p12, eng
		var description: String {
			switch self {
			case .pem: return "PEM"
			case .der: return "DER"
			case .p12: return "P12"
			case .eng: return "ENG"
			}
		}
	}

	/// The numerous options which can be set. Each enum case indicates the parameter type(s) for the option.
	public enum Option {
	case
		/// The URL for the request.
		url(String),
		/// Override the port for the request.
		port(Int),
		/// Fail on http error codes >= 400.
		failOnError,
		/// Colon separated username/password string.
		userPwd(String),
		/// Proxy server address.
		proxy(String),
		/// Proxy server username/password combination.
		proxyUserPwd(String),
		/// Port override for the proxy server.
		proxyPort(Int),
		/// Maximum time in seconds for the request to complete.
		/// The default timeout is never.
		timeout(Int),
		/// Maximum time in seconds for the request connection phase.
		/// The default timeout is 300 seconds.
		connectTimeout(Int),
		/// The average transfer speed in bytes per second that the transfer should be below 
		/// during `.lowSpeedLimit` seconds for the request to be too slow and abort.
		lowSpeedLimit(Int),
		/// The time in seconds that the transfer speed should be below the `.lowSpeedLimit` 
		/// for therequest to be considered too slow and aborted.
		lowSpeedTime(Int),
		/// Range request value as a string in the format "X-Y", where either X or Y may be 
		/// left out and X and Y are byte indexes
		range(String),
		/// The offset in bytes at which the request should start form.
		resumeFrom(Int),
		/// Set one or more cookies for the request. Should be in the format "name=value".
		/// Separate multiple cookies with a semi-colon: "name1=value1; name2=value2".
		cookie(String),
		/// The name of the file holding cookie data for the request.
		cookieFile(String),
		/// The name opf the file to which received cookies will be written.
		cookieJar(String),
		/// Indicated that the request should follow redirects. Default is false.
		followLocation(Bool),
		/// Maximum number of redirects the request should follow. Default is unlimited.
		maxRedirects(Int),
		/// Maximum number of simultaneously open persistent connections that may cached for the request.
		maxConnects(Int),
		/// When enabled, the request will automatically set the Referer: header field in HTTP 
		/// requests when it follows a Location: redirect
		autoReferer(Bool),
		/// Sets the kerberos security level for FTP.
		/// Value should be one of the following: .clear, .safe, .confidential or .private.
		krbLevel(KBRLevel),
		/// Add a header to the request.
		addHeader(Header.Name, String),
		/// Add a series of headers to the request.
		addHeaders([(Header.Name, String)]),
		/// Add or replace a header.
		replaceHeader(Header.Name, String),
		/// Remove a default internally added header.
		removeHeader(Header.Name),
		/// Set the Accept-Encoding header and enable decompression of response data.
		acceptEncoding(String),
		/// Path to the client SSL certificate.
		sslCert(String),
		/// Specifies the type for the client SSL certificate. Defaults to `.pem`.
		sslCertType(SSLFileType),
		/// Path to client private key file.
		sslKey(String),
		/// Password to be used if the SSL key file is password protected.
		sslKeyPwd(String),
		/// Specifies the type for the SSL private key file.
		sslKeyType(SSLFileType),
		/// Force the request to use a specific version of TLS or SSL.
		sslVersion(TLSMethod),
		/// Inticates whether the request should verify the authenticity of the peer's certificate.
		sslVerifyPeer(Bool),
		/// Indicates whether the request should verify that the server cert is for the server it is known as.
		sslVerifyHost(Bool),
		/// Path to file holding one or more certificates which will be used to verify the peer.
		sslCAFilePath(String),
		/// Path to directory holding one or more certificates which will be used to verify the peer.
		sslCADirPath(String),
		/// Override the list of ciphers to use for the SSL connection. 
		/// Consists of one or more cipher strings separated by colons. Commas or spaces are also acceptable 
		/// separators but colons are normally used. "!", "-" and "+" can be used as operators.
		sslCiphers([String]),
		/// File path to the pinned public key.
		/// When negotiating a TLS or SSL connection, the server sends a certificate indicating its 
		/// identity. A public key is extracted from this certificate and if it does not exactly 
		/// match the public key provided to this option, curl will abort the connection before 
		/// sending or receiving any data.
		sslPinnedPublicKey(String),
		/// List of (S)FTP commands to be run before the file transfer.
		ftpPreCommands([String]),
		/// List of (S)FTP commands to be run after the file transfer.
		ftpPostCommands([String]),
		/// Specifies the local connection port for active FTP transfers.
		ftpPort(String),
		/// The time in seconds that the request will wait for FTP server responses.
		ftpResponseTimeout(Int),
		/// Path to the public key file used for SSH connections.
		sshPublicKey(String),
		/// Path to the private key file used for SSH connections.
		sshPrivateKey(String),
		/// HTTP method to be used for the request.
		httpMethod(HTTPMethod),
		/// Adds a single POST field to the request. Generally, multiple POSt fields are added for a request.
		postField(POSTField),
		/// Raw bytes to be used for a POST request.
		postData([UInt8]),
		/// Raw string data to be used for a POST request.
		postString(String),
		/// Specifies the sender's address when performing an SMTP request.
		mailFrom(String),
		/// Specifies the recipient when performing an SMTP request. 
		/// Multiple recipients may be specified by using this option multiple times.
		mailRcpt(String),
		/// CURL verbose mode.
		verbose,
		/// Include headers in response body.
		header,
		/// This connection will be using SSL. (when is this needed? SMTP only?)
		useSSL,
		/// Indicate that the request will be an upload.
		/// And provide an object to incrementally provide the content.
		upload(CURLRequestBodyGenerator),
		/// Indicate that the request will be an upload.
		/// And provide a local file path for the file to be uploaded.
		uploadFile(String)
	}
	let curl: CURL
	/// Mutable options array for the request. These options are cleared when the request is .reset()
	public var options: [Option]
	var postFields: POSTFields?
	var uploadBodyGen: CURLRequestBodyGenerator?
	/// Init with a url and options array.
	public convenience init(_ url: String, options: [Option] = []) {
		self.init(options: [.url(url)] + options)
	}
	/// Init with url and one or more options.
	public convenience init(_ url: String, _ option1: Option, _ options: Option...) {
		self.init(options: [.url(url)] + [option1] + options)
	}
	/// Init with array of options.
	public init(options: [Option] = []) {
		curl = CURL()
		self.options = options
	}
	func applyOptions() {
		options.forEach { $0.apply(to: self) }
		if let postFields = self.postFields {
			curl.formAddPost(fields: postFields)
		}
	}
}

public extension CURLRequest {
	/// Execute the request synchronously. 
	/// Returns the response or throws an Error.
	func perform() throws -> CURLResponse {
		applyOptions()
		let resp = CURLResponse(curl, postFields: postFields)
		try resp.complete()
		return resp
	}

	/// Execute the request asynchronously.
	/// The parameter passed to the completion callback must be called to obtain the response or throw an Error.
	func perform(_ completion: @escaping (CURLResponse.Confirmation) -> ()) {
		applyOptions()
		CURLResponse(curl, postFields: postFields).complete(completion)
	}

	/// Execute the request asynchronously. 
	/// Returns a Promise object which can be used to monitor the operation.
	func promise() -> Promise<CURLResponse> {
		return Promise { p in
			self.perform { confirmation in
				do {
					p.set(try confirmation())
				} catch {
					p.fail(error)
				}
			}
		}
	}

	/// Reset the request. Clears all options so that the object can be reused.
	/// New options can be provided.
	func reset(_ options: [Option] = []) {
		curl.reset()
		postFields = nil
		uploadBodyGen = nil
		self.options = options
	}

	/// Reset the request. Clears all options so that the object can be reused.
	/// New options can be provided.
	func reset(_ option: Option, _ options: Option...) {
		reset([option] + options)
	}
}

public extension CURLRequest {
	/// Add a header to the response.
	/// No check for duplicate or repeated headers will be made.
	func addHeader(_ named: Header.Name, value: String) {
		options.append(.addHeader(named, value))
	}
	/// Set the indicated header value.
	/// If the header already exists then the existing value will be replaced.
	func replaceHeader(_ named: Header.Name, value: String) {
		options.append(.replaceHeader(named, value))
	}
	/// Remove the indicated header.
	func removeHeader(_ named: Header.Name) {
		options.append(.removeHeader(named))
	}
}
