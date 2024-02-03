//
//  JWK.swift
//  PerfectCrypto
//
//  Created by Kyle Jessup on 2020-03-08.
//

import COpenSSL
import Foundation

func BN_num_bytes(_ bn: UnsafeMutablePointer<BIGNUM>) -> Int32 {
	return ((BN_num_bits(bn)+7)/8)
}

public struct JWK: Codable {
	public struct Key: Codable {
		public let kty: String
		public let kid: String
		public var e: String? = nil
		public var n: String? = nil
		public var d: String? = nil
		init(key: PEMKey) throws {
			kid = UUID().uuidString
			let pkey = key.pkey
			switch key.type {
			case .rsa:
				kty = "RSA"
				var ke: UnsafePointer<BIGNUM>?
				var kn: UnsafePointer<BIGNUM>?
				var kd: UnsafePointer<BIGNUM>?
				if let rsa = EVP_PKEY_get1_RSA(pkey) {
					RSA_get0_key(rsa, &kn, &ke, &kd)
					n = encnum(kn)
					e = encnum(ke)
					d = encnum(kd)
				}
			case .dsa:
				kty = "DSA"
				_ = EVP_PKEY_get1_DSA(pkey)
				throw CryptoError(code: -1, msg: "Not implemented.")
			case .ec:
				kty = "EC"
				_ = EVP_PKEY_get1_EC_KEY(pkey)
				throw CryptoError(code: -1, msg: "Not implemented.")
			}
		}
		private func encnum(_ kn: UnsafePointer<BIGNUM>?) -> String? {
			if let kn = kn {
				let len = BN_num_bytes(UnsafeMutablePointer(mutating: kn))
				let ptr = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: Int(len))
				defer {
					ptr.deallocate()
				}
				BN_bn2bin(kn, ptr.baseAddress)
				if let encoded = UnsafeRawBufferPointer(ptr).encode(.base64url) {
					return String(validatingUTF8: UnsafeRawBufferPointer(encoded))
				}
			}
			return nil
		}
	}
	public let keys: [Key]
	public init(key: PEMKey) throws {
		try self.init(keys: [key])
	}
	public init(keys: PEMKey, pems: PEMKey...) throws {
		try self.init(keys: [keys] + pems)
	}
	public init(keys pems: [PEMKey]) throws {
		keys = try pems.map { try Key(key: $0) }
	}
}
