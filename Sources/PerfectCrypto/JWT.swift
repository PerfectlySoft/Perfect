//
//  JWT.swift
//  PerfectCrypto
//
//  Created by Kyle Jessup on 2017-03-13.
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

import COpenSSL
import PerfectLib
import Foundation

private let dot = UInt8(46)
private let jwtEncoding = Encoding.base64url

/// Types used by both JWTCreator and JWTVerifier
public struct JWT {
	/// Supported JWT alg types
	public enum Alg {
		case hs256, hs384, hs512
		case rs256, rs384, rs512
		case es256, es384, es512
		case none
	}
	/// A signing or validation error
	public enum Error: Swift.Error {
		case verificationError(String)
		case signingError(String)
	}
}

/// Accepts a JWT token string and verifies its structural validity and signature.
public struct JWTVerifier {
	let headerBytes: [UInt8]
	let payloadBytes: [UInt8]
	let signatureBytes: [UInt8]
	/// The headers obtained from the token.
	public var header: [String: Any] {
		return (try? String(validatingUTF8: headerBytes)?.jsonDecode()) as? [String: Any] ?? [:]
	}
	/// The payload carried by the token.
	public var payload: [String: Any] {
		return (try? payloadString?.jsonDecode()) as? [String: Any] ?? [:]
	}
	// Payload data as UTF-8
	public var payloadString: String? {
		return String(validatingUTF8: payloadBytes)
	}

	/// Create a JWTVerifier given a source string in the "aaaa.bbbb.cccc" format.
	/// Returns nil if the given string is not a valid JWT.
	/// *Does not perform verification in this step.* Call `verify` with your key to validate.
	/// If verification succeeds then the `.headers` and `.payload` properties can be safely accessed.
	public init?(_ jwt: String) {
		let split = jwt.utf8.split(separator: dot, omittingEmptySubsequences: false)
		#if swift(>=4.1)
		let decoded = split.compactMap { $0.map { $0 }.decode(jwtEncoding) }
		#else
		let decoded = split.flatMap { $0.map { $0 }.decode(jwtEncoding) }
		#endif
		guard decoded.count == 3 else {
			return nil
		}
		headerBytes = decoded[0]
		payloadBytes = decoded[1]
		signatureBytes = decoded[2]
	}

	/// Verify the token based on the indicated algorithm and HMAC key.
	/// Throws a JWT.Error.verificationError if any aspect of the token is incongruent.
	/// Returns without any error if the token was able to be verified.
	/// The parameter `algo` must match the token's "alg" header.
	public func verify(algo: JWT.Alg, key: String) throws {
		return try verify(algo: algo, key: HMACKey(key))
	}

	/// Verify the token based on the indicated algorithm and key.
	/// Throws a JWT.Error.verificationError if any aspect of the token is incongruent.
	/// Returns without any error if the token was able to be verified.
	/// The parameter `algo` must match the token's "alg" header.
	/// The key type must be compatible with the indicated `algo`.
	public func verify(algo: JWT.Alg, key: Key) throws {
		let header = self.header
		guard header["alg"] as? String == algo.string else {
			throw JWT.Error.verificationError("alg mismatch. expected \(algo.string) got \(String(describing: header["alg"]))")
		}
		if case .none = algo {
			return
		}
		guard let header64 = headerBytes.encode(jwtEncoding),
			let payload64 = payloadBytes.encode(jwtEncoding) else {
				throw JWT.Error.verificationError("Internal error. Unable to base64url encode header and payload.")
		}
		let part1 = header64 + [dot] + payload64
		guard try verify(part1, signature: signatureBytes, algo: algo, key: key) else {
			throw JWT.Error.verificationError("Signatures did not match.")
		}
	}

	func verify(_ data: [UInt8], signature: [UInt8], algo: JWT.Alg, key: Key) throws -> Bool {
		if case .none = algo {
			return true
		}
		guard let digest = algo.digest else {
			throw JWT.Error.signingError("Digest \(algo.string) not supported")
		}
		return data.verify(digest, signature: signature, key: key)
	}
}

/// Creates and signs new JWT tokens.
public struct JWTCreator {
	let payloadBytes: [UInt8]
	/// Creates a new JWT given a payload.
	/// The payload can then be signed to generate a JWT token string.
	public init?(payload: [String: Any]) {
		guard let json = try? payload.jsonEncodedString() else {
			return nil
		}
		payloadBytes = Array(json.utf8)
    }
	/// Sign and return a new JWT token string using an HMAC key.
	/// Additional headers can be optionally provided.
	/// Throws a JWT.Error.signingError if there is a problem generating the token string.
	public func sign(alg: JWT.Alg, key: String, headers: [String: Any] = [:]) throws -> String {
		return try sign(alg: alg, key: HMACKey(key), headers: headers)
	}
	/// Sign and return a new JWT token string using the given key.
	/// Additional headers can be optionally provided.
	/// The key type must be compatible with the indicated `algo`.
	/// Throws a JWT.Error.signingError if there is a problem generating the token string.
	public func sign(alg: JWT.Alg, key: Key, headers: [String: Any] = [:]) throws -> String {
		var useHeaders: [String: Any] = ["alg": alg.string, "typ": "JWT"]
		headers.forEach {key, value in
			useHeaders[key] = value
		}
		let headerBytes = Array(try useHeaders.jsonEncodedString().utf8)
		guard let h64 = headerBytes.encode(jwtEncoding),
			let p64 = payloadBytes.encode(jwtEncoding) else {
				throw JWT.Error.signingError("Internal error. Unable to base64url encode header and payload.")
		}
		let part1 = h64 + [dot] + p64
		let sig = try sign(part1, algo: alg, key: key)
		guard let s64 = sig.encode(jwtEncoding),
			let ret = String(validatingUTF8: part1 + [dot] + s64) else {
				throw JWT.Error.signingError("Invalid resulting JWT")
		}
		return ret
	}

	func sign(_ data: [UInt8], algo: JWT.Alg, key: Key) throws -> [UInt8] {
		if case .none = algo {
			return []
		}
		guard let digest = algo.digest else {
			throw JWT.Error.signingError("Digest \(algo.string) not supported")
		}
		guard let bytes = data.sign(digest, key: key) else {
			throw JWT.Error.signingError("Fatal error during signing")
		}
		return bytes
	}
}

public extension JWTCreator {
	/// Create a new JWT given a Codable object.
	/// The payload can then be signed to generate a JWT token string.
	init<T: Codable>(payload: T) throws {
		let json = try JSONEncoder().encode(payload)
		payloadBytes = Array(json)
	}
}

public extension JWTVerifier {
	func verify<T: Codable>(algo: JWT.Alg, key: Key, as: T.Type) throws -> T {
		try verify(algo: algo, key: key)
		return try JSONDecoder().decode(`as`, from: Data(payloadBytes))
	}
	func verify<T: Codable>(algo: JWT.Alg, key: String, as: T.Type) throws -> T {
		try verify(algo: algo, key: key)
		return try JSONDecoder().decode(`as`, from: Data(payloadBytes))
	}
	func decode<T: Codable>(as: T.Type) throws -> T {
		return try JSONDecoder().decode(`as`, from: Data(payloadBytes))
	}
}

extension JWT.Alg {
	init?(_ string: String) {
		switch string {
		case "HS256": self = .hs256
		case "HS384": self = .hs384
		case "HS512": self = .hs512
		case "RS256": self = .rs256
		case "RS384": self = .rs384
		case "RS512": self = .rs512
		case "ES256": self = .es256
		case "ES384": self = .es384
		case "ES512": self = .es512
		case "none": self = .none
		default: return nil
		}
	}
	var digest: Digest? {
		switch self {
		case .hs256, .rs256, .es256: return .sha256
		case .hs384, .rs384, .es384: return .sha384
		case .hs512, .rs512, .es512: return .sha512
		case .none:
			return nil
		}
	}
	var string: String {
		switch self {
		case .hs256: return "HS256"
		case .hs384: return "HS384"
		case .hs512: return "HS512"
		case .rs256: return "RS256"
		case .rs384: return "RS384"
		case .rs512: return "RS512"
		case .es256: return "ES256"
		case .es384: return "ES384"
		case .es512: return "ES512"
		case .none: return "none"
		}
	}
}
