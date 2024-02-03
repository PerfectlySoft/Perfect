//
//  Keys.swift
//  PerfectCrypto
//
//  Created by Kyle Jessup on 2017-02-13.
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

public struct KeyError: Error {
	public let msg: String
	init(_ msg: String) {
		self.msg = msg
	}
}

public class Key {
	let pkey: UnsafeMutablePointer<EVP_PKEY>?
	deinit {
		EVP_PKEY_free(pkey)
	}
	init(_ key: UnsafeMutablePointer<EVP_PKEY>?) {
		self.pkey = key
	}
}

public class HMACKey: Key {
	public convenience init(_ key: String) {
		self.init(key.utf8.map { UInt8($0) })
	}
	public init(_ key: [UInt8]) {
		let p = key.withUnsafeBytes { (p: UnsafeRawBufferPointer) -> UnsafeMutablePointer<EVP_PKEY> in
			return EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, nil,
										p.bindMemory(to: UInt8.self).baseAddress,
										Int32(p.count))
		}
		super.init(p)
	}
}

public enum PEMKeyType {
	case rsa, dsa, ec
}

public class PEMKey: Key {
	public var type: PEMKeyType {
		let typeId = EVP_PKEY_base_id(pkey)
		switch typeId {
		case EVP_PKEY_RSA: return .rsa
		case EVP_PKEY_DSA: return .dsa
		case EVP_PKEY_EC: return .ec
		default:
			return .rsa
		}
	}
	init(kp: UnsafeMutablePointer<EVP_PKEY>?) {
		super.init(kp)
	}
	public convenience init(pemPath: String) throws {
		try self.init(source: try File(pemPath).readString())
	}
	public init(source original: String) throws {
		let source = PEMKey.cleanSource(original)
		var kp: UnsafeMutablePointer<EVP_PKEY>? = nil
		func tryOne(_ call: (MemoryIO) throws -> ()) throws -> Bool {
			let f = MemoryIO(source)
			try call(f)
			return nil != kp
		}
		do { // rsa
			if try tryOne({ f in
				if let rsa = PEM_read_bio_RSAPrivateKey(f.bio, nil, nil, nil) {
					kp = EVP_PKEY_new()
					guard 1 == EVP_PKEY_assign(kp, EVP_PKEY_RSA, rsa) else {
						RSA_free(rsa)
						EVP_PKEY_free(kp)
						throw KeyError("No public or private key could be read. Could not fetch RSA private key.")
					}
				}
			}) {
				super.init(kp)
				return
			}
			if try tryOne({ f in
				if let rsa = PEM_read_bio_RSAPublicKey(f.bio, nil, nil, nil) {
					kp = EVP_PKEY_new()
					guard 1 == EVP_PKEY_assign(kp, EVP_PKEY_RSA, rsa) else {
						RSA_free(rsa)
						EVP_PKEY_free(kp)
						throw KeyError("No public or private key could be read. Could not fetch RSA public key.")
					}
				}
			}) {
				super.init(kp)
				return
			}
		}
		do { // dsa
			if try tryOne({ f in
				if let dsa = PEM_read_bio_DSAPrivateKey(f.bio, nil, nil, nil) {
					kp = EVP_PKEY_new()
					guard 1 == EVP_PKEY_assign(kp, EVP_PKEY_DSA, dsa) else {
						DSA_free(dsa)
						EVP_PKEY_free(kp)
						throw KeyError("No public or private key could be read. Could not fetch DSA private key.")
					}
				}
			}) {
				super.init(kp)
				return
			}
			if try tryOne({ f in
				if let dsa = PEM_read_bio_DSA_PUBKEY(f.bio, nil, nil, nil) {
					kp = EVP_PKEY_new()
					guard 1 == EVP_PKEY_assign(kp, EVP_PKEY_DSA, dsa) else {
						DSA_free(dsa)
						EVP_PKEY_free(kp)
						throw KeyError("No public or private key could be read. Could not fetch DSA public key.")
					}
				}
			}) {
				super.init(kp)
				return
			}
		}
		do { // ec
			if try tryOne({ f in
				if let ec = PEM_read_bio_ECPrivateKey(f.bio, nil, nil, nil) {
					kp = EVP_PKEY_new()
					guard 1 == EVP_PKEY_assign(kp, EVP_PKEY_EC, UnsafeMutableRawPointer(ec)) else {
						EC_KEY_free(ec)
						EVP_PKEY_free(kp)
						throw KeyError("No public or private key could be read. Could not fetch EC private key.")
					}
				}
			}) {
				super.init(kp)
				return
			}
			if try tryOne({ f in
				if let ec = PEM_read_bio_EC_PUBKEY(f.bio, nil, nil, nil) {
					kp = EVP_PKEY_new()
					guard 1 == EVP_PKEY_assign(kp, EVP_PKEY_EC, UnsafeMutableRawPointer(ec)) else {
						EC_KEY_free(ec)
						EVP_PKEY_free(kp)
						throw KeyError("No public or private key could be read. Could not fetch EC public key.")
					}
				}
			}) {
				super.init(kp)
				return
			}
		}
		if try tryOne({ f in
			if let x509 = PEM_read_bio_X509(f.bio, nil, nil, nil) {
				kp = X509_get_pubkey(x509)
				X509_free(x509)
			}
		}) {
			super.init(kp)
			return
		}
		if try tryOne({	PEM_read_bio_PrivateKey($0.bio, &kp, nil, nil) }) {
			super.init(kp)
			return
		}
		if try tryOne({	PEM_read_bio_PUBKEY($0.bio, &kp, nil, nil) }) {
			super.init(kp)
			return
		}
		throw KeyError("No public or private key could be read.")
	}
	public init(type: PEMKeyType, bits: Int, exp: Int = RSA_F4) throws {
		var kp: UnsafeMutablePointer<EVP_PKEY>?
		switch type {
		case .rsa:
			let ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nil)
			guard 1 == EVP_PKEY_keygen_init(ctx),
				1 == EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_KEYGEN,
										 EVP_PKEY_CTRL_RSA_KEYGEN_BITS, Int32(bits), nil),
				1 == EVP_PKEY_keygen(ctx, &kp) else {
				try CryptoError.throwOpenSSLError()
			}
		case .dsa:
			let dsa = DSA_new()
			DSA_generate_parameters_ex(dsa, Int32(bits), nil, 0, nil, nil, nil)
			guard 1 == DSA_generate_key(dsa) else {
				try CryptoError.throwOpenSSLError()
			}
			kp = EVP_PKEY_new()
			EVP_PKEY_assign(kp, EVP_PKEY_DSA, dsa)
		case .ec:
			let curve = "secp521r1"
			let eccgrp = OBJ_txt2nid(curve)
			let ecc = EC_KEY_new_by_curve_name(eccgrp)
			EC_KEY_set_asn1_flag(ecc, OPENSSL_EC_NAMED_CURVE)
			guard 1 == EC_KEY_generate_key(ecc) else {
				try CryptoError.throwOpenSSLError()
			}
			kp = EVP_PKEY_new()
			EVP_PKEY_assign(kp, EVP_PKEY_EC, UnsafeMutableRawPointer(ecc))
		}
		super.init(kp)
	}
	static func cleanSource(_ source: String) -> String {
		var inHeader = true
		let charMax = 64
		var charCount = 0
		var accum = ""
		source.forEach { c in
			switch c {
			case "\r", "\n", "\r\n":
				if inHeader {
					inHeader = false
					accum += "\n"
					charCount = 0
				}
			case "-":
				if !inHeader {
					accum += "\n"
					charCount = 0
				}
				inHeader = true
				accum += "-"
				charCount += 1
			default:
				if charCount == charMax {
					accum += "\n"
					charCount = 0
				} else {
					charCount += 1
				}
				accum += String(c)
			}
		}
		if inHeader {
			accum += "\n"
		}
		return accum
	}
}

extension PEMKey: CustomStringConvertible {
	public var description: String {
		let mem = MemoryIO()
		PEM_write_bio_PrivateKey(mem.bio, pkey, nil, nil, 0, nil, nil)
		PEM_write_bio_PUBKEY(mem.bio, pkey)
		return String(validatingUTF8: mem.memory) ?? ""
	}
	public var privateKeyString: String? {
		let mem = MemoryIO()
		let result: Int32
		switch type {
		case .rsa:
			let rsa = EVP_PKEY_get1_RSA(pkey)
			result = PEM_write_bio_RSAPrivateKey(mem.bio, rsa, nil, nil, 0, nil, nil)
		case .dsa:
			let dsa = EVP_PKEY_get1_DSA(pkey)
			result = PEM_write_bio_DSAPrivateKey(mem.bio, dsa, nil, nil, 0, nil, nil)
		case .ec:
			let ec = EVP_PKEY_get1_EC_KEY(pkey)
			result = PEM_write_bio_ECPrivateKey(mem.bio, ec, nil, nil, 0, nil, nil)
		}
		guard 1 == result else { // 1 == PEM_write_bio_PUBKEY(mem.bio, pkey) else {
			return nil
		}
		return String(validatingUTF8: mem.memory)
	}
	public var publicKeyString: String? {
		let mem = MemoryIO()
		let result: Int32
		switch type {
		case .rsa:
			let rsa = EVP_PKEY_get1_RSA(pkey)
			result = PEM_write_bio_RSAPublicKey(mem.bio, rsa)
		case .dsa:
			let dsa = EVP_PKEY_get1_DSA(pkey)
			result = PEM_write_bio_DSA_PUBKEY(mem.bio, dsa)
		case .ec:
			let ec = EVP_PKEY_get1_EC_KEY(pkey)
			result = PEM_write_bio_EC_PUBKEY(mem.bio, ec)
		}
		guard 1 == result else { // 1 == PEM_write_bio_PUBKEY(mem.bio, pkey) else {
			return nil
		}
		return String(validatingUTF8: mem.memory)
	}

	public var privateKey: PEMKey? {
		guard let str = privateKeyString else {
			return nil
		}
		return try? PEMKey(source: str)
	}
	public var publicKey: PEMKey? {
		guard let str = publicKeyString else {
			return nil
		}
		return try? PEMKey(source: str)
	}
}
