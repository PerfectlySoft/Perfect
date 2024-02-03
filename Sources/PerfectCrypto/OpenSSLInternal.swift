//
//  OpenSSLInternal.swift
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

import COpenSSL
import PerfectThread
#if os(Linux)
    import SwiftGlibc
#else
	import Darwin
#endif

private var openSSLLocks: [Threading.Lock] = []

struct OpenSSLInternal {
	static var isInitialized: Bool = {
		copenssl_SSL_library_init()
		for i in 0..<Int(CRYPTO_num_locks()) {
			openSSLLocks.append(Threading.Lock())
		}
		let lockingCallback: @convention(c) (Int32, Int32, UnsafePointer<Int8>?, Int32) -> () = { (mode: Int32, n: Int32, _: UnsafePointer<Int8>?, _: Int32) in
			if (mode & CRYPTO_LOCK) != 0 {
				openSSLLocks[Int(n)].lock()
			} else {
				openSSLLocks[Int(n)].unlock()
			}
		}
		CRYPTO_set_locking_callback(lockingCallback)

		let threadIdCallback: @convention(c) () -> UInt = {
		#if os(Linux)
			return pthread_self()
		#else
			return UInt(bitPattern: pthread_self())
		#endif
		}

		CRYPTO_set_id_callback(threadIdCallback)
		return true
	}()
}

extension CryptoError {
	init() {
		let errorCode = ERR_get_error()
		let maxLen = 1024
		let buf = UnsafeMutablePointer<Int8>.allocate(capacity: maxLen)
		defer {
			buf.deallocate()
		}
		ERR_error_string_n(errorCode, buf, maxLen)
		let msg = String(validatingUTF8: buf) ?? ""
		self.init(code: Int(errorCode), msg: msg)
	}
	static func throwOpenSSLError() throws -> Never {
		throw CryptoError()
	}
}

private let plus = UInt8(43)
private let dash = UInt8(45)
private let fslash = UInt8(47)
private let uscore = UInt8(95)
private let equal = UInt8(61)

extension Encoding {
	func encodeBytes(_ source: UnsafeRawBufferPointer) -> UnsafeMutableRawBufferPointer? {
		switch self {
		case .base64:
			return toBytesBase64(source)
		case .base64url:
			return toBytesBase64URL(source)
		case .hex:
			return toBytesHex(source)
		}
	}

	func decodeBytes(_ source: UnsafeRawBufferPointer) -> UnsafeMutableRawBufferPointer? {
		switch self {
		case .base64:
			return fromBytesBase64(source)
		case .base64url:
			return fromBytesBase64URL(source)
		case .hex:
			return fromBytesHex(source)
		}
	}

	private func toBytesBase64(_ source: UnsafeRawBufferPointer) -> UnsafeMutableRawBufferPointer? {
		let chain = Base64Filter().chain(MemoryIO())
		do {
			_ = try chain.write(bytes: source)
			try chain.flush()
			let length = chain.readPending
			guard let memory = chain.memory else {
				return nil
			}
			let ret = UnsafeMutableRawBufferPointer.allocate(byteCount: length, alignment: 0)
			#if swift(>=4.1)
			ret.copyMemory(from: memory)
			#else
			ret.copyBytes(from: memory)
			#endif
			return ret
		} catch {
			return nil
		}
	}

	private func fromBytesBase64(_ source: UnsafeRawBufferPointer) -> UnsafeMutableRawBufferPointer? {
		let chain = Base64Filter().chain(MemoryIO(source))
		do {
			let ret = UnsafeMutableRawBufferPointer.allocate(byteCount: source.count, alignment: 0)
			let count = try chain.read(ret)
			return UnsafeMutableRawBufferPointer(start: ret.baseAddress, count: count)
		} catch {
			return nil
		}
	}

	private func toBytesBase64URL(_ source: UnsafeRawBufferPointer) -> UnsafeMutableRawBufferPointer? {
		let chain = Base64Filter().chain(MemoryIO())
		do {
			_ = try chain.write(bytes: source)
			try chain.flush()
			var length = chain.readPending
			guard let memory = chain.memory else {
				return nil
			}
			while length > 0 {
				if memory[length-1] == equal {
					length -= 1
				} else {
					break
				}
			}
			let ret = UnsafeMutableRawBufferPointer.allocate(byteCount: length, alignment: 0)
			for i in 0..<length {
				switch memory[i] {
				case plus:
					ret[i] = dash
				case fslash:
					ret[i] = uscore
				default:
					ret[i] = memory[i]
				}
			}
			return ret
		} catch {
			return nil
		}
	}

	private func fromBytesBase64URL(_ source: UnsafeRawBufferPointer) -> UnsafeMutableRawBufferPointer? {
		var deurled: [UInt8] = source.map {
			switch $0 {
			case dash:
				return plus
			case uscore:
				return fslash
			default:
				return $0
			}
		}
		for _ in 0..<(deurled.count % 4) {
			deurled.append(equal)
		}
		let chain = deurled.withUnsafeBytes { Base64Filter().chain(MemoryIO($0)) }
		do {
			let ret = UnsafeMutableRawBufferPointer.allocate(byteCount: deurled.count, alignment: 0)
			let count = try chain.read(ret)
			return UnsafeMutableRawBufferPointer(start: ret.baseAddress, count: count)
		} catch {
			return nil
		}
	}

	private func toBytesHex(_ source: UnsafeRawBufferPointer) -> UnsafeMutableRawBufferPointer? {
		let sourceCount = source.count
		let ret = UnsafeMutableRawBufferPointer.allocate(byteCount: sourceCount * 2, alignment: 0)
		var ri = 0
		for i in 0..<sourceCount {
			let byte = source[i]
			let b1 = byte >> 4
			let b2 = byte & 0x0F
			let nb1 = b1 > 9 ? b1 - 10 + 97 : b1 + 48
			let nb2 = b2 > 9 ? b2 - 10 + 97 : b2 + 48
			ret[ri] = nb1
			ret[ri+1] = nb2
			ri += 2
		}
		return ret
	}

	private func fromBytesHex(_ source: UnsafeRawBufferPointer) -> UnsafeMutableRawBufferPointer? {
		let sourceCount = source.count
		guard sourceCount % 2 == 0 else {
			return nil
		}
		let ret = UnsafeMutableRawBufferPointer.allocate(byteCount: sourceCount / 2, alignment: 0)
		var ri = 0
		for index in stride(from: source.startIndex, to: source.endIndex, by: 2) {
			guard let c = UInt8(hexOne: source[index], hexTwo: source[index+1]) else {
				return nil
			}
			ret[ri] = c
			ri += 1
		}
		return ret
	}

	private func byteFromHexDigits(one c1v: UInt8, two c2v: UInt8) -> UInt8? {

		let capA: UInt8 = 65
		let capF: UInt8 = 70
		let lowA: UInt8 = 97
		let lowF: UInt8 = 102
		let zero: UInt8 = 48
		let nine: UInt8 = 57

		var newChar = UInt8(0)

		if c1v >= capA && c1v <= capF {
			newChar = c1v - capA + 10
		} else if c1v >= lowA && c1v <= lowF {
			newChar = c1v - lowA + 10
		} else if c1v >= zero && c1v <= nine {
			newChar = c1v - zero
		} else {
			return nil
		}

		newChar *= 16

		if c2v >= capA && c2v <= capF {
			newChar += c2v - capA + 10
		} else if c2v >= lowA && c2v <= lowF {
			newChar += c2v - lowA + 10
		} else if c2v >= zero && c2v <= nine {
			newChar += c2v - zero
		} else {
			return nil
		}
		return newChar
	}
}

func internal_RAND_bytes(into: UnsafeMutableRawBufferPointer) -> Int {
	guard let p = into.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
		return 0
	}
	return Int(RAND_bytes(p, Int32(into.count)))
}

extension Digest {
	func bio() -> UnsafePointer<BIO>? {
		let md = self.evp
		let bio = BIO_new(BIO_f_md())
		BIO_ctrl(bio, BIO_C_SET_MD, 1, UnsafeMutableRawPointer(mutating: md))
		return UnsafePointer(bio)
	}
	var evp: UnsafePointer<EVP_MD> {
		switch self {
		case .md4:		  return EVP_md4()
		case .md5:		  return EVP_md5()
		case .sha1:		  return EVP_sha1()
		case .sha224:	  return EVP_sha224()
		case .sha256:	  return EVP_sha256()
		case .sha384:	  return EVP_sha384()
		case .sha512:	  return EVP_sha512()
		case .ripemd160:  return EVP_ripemd160()
		case .whirlpool:  return EVP_whirlpool()
		case .custom(let name):	  return EVP_get_digestbyname(name)
		}
	}
	var length: Int {
		return Int(copenssl_EVP_MD_size(evp))
	}

	func sign(_ data: UnsafeRawBufferPointer, privateKey key: Key) -> UnsafeMutableRawBufferPointer? {
		guard let ctx = copenssl_EVP_MD_CTX_create() else {
			return nil
		}
		defer {
			copenssl_EVP_MD_CTX_destroy(ctx)
		}
		guard 1 == EVP_DigestSignInit(ctx, nil, self.evp, nil, key.pkey) else {
			return nil
		}
		guard 1 == EVP_DigestUpdate(ctx, data.baseAddress, data.count) else {
			return nil
		}
		var mdLen = 0
		guard 1 == EVP_DigestSignFinal(ctx, nil, &mdLen) else {
			return nil
		}
		let ret = UnsafeMutableRawBufferPointer.allocate(byteCount: mdLen, alignment: 0)
		var finalLen = mdLen
		guard 1 == EVP_DigestSignFinal(ctx, ret.baseAddress?.assumingMemoryBound(to: UInt8.self), &finalLen) else {
			ret.deallocate()
			return nil
		}
		if finalLen < mdLen {
			return UnsafeMutableRawBufferPointer(start: ret.baseAddress, count: finalLen)
		}
		return ret
	}
	func verify(_ data: UnsafeRawBufferPointer, signature: UnsafeRawBufferPointer, publicKey key: Key) -> Bool {

		if key is HMACKey {
			guard let signed = data.sign(self, key: key) else {
				return false
			}
			defer {
				signed.deallocate()
			}
			guard signed.count == signature.count else {
				return false
			}
			return 0 == CRYPTO_memcmp(signed.baseAddress, signature.baseAddress, signed.count)
		}

		guard let ctx = copenssl_EVP_MD_CTX_create() else {
			return false
		}
		defer {
			copenssl_EVP_MD_CTX_destroy(ctx)
		}
		guard 1 == EVP_DigestVerifyInit(ctx, nil, evp, nil, key.pkey) else {
			return false
		}
		guard 1 == EVP_DigestUpdate(ctx, data.baseAddress, data.count) else {
			return false
		}
		let mdLen = signature.count
		guard 1 == EVP_DigestVerifyFinal(ctx, signature.baseAddress?.assumingMemoryBound(to: UInt8.self), mdLen) else {
			return false
		}
		return true
	}

	/// Derive a suitable encryption key based on a password and salt.
	/// The "PKCS5 PBKDF2 HMAC" algorithm will be used to generate the key.
	/// The `iterations` parameter should generally be a number greater than 1000.
	/// The `keyLength` parameter should indicate the desired key length and will generally match the `keyLength` of a cipher.
	public func deriveKey(password: String, salt: String, iterations: Int, keyLength: Int) -> [UInt8]? {
		return deriveKey(password: Array(password.utf8),
		                 salt: Array(salt.utf8),
		                 iterations: iterations, keyLength: keyLength)
	}

	/// Derive a suitable encryption key based on a password and salt.
	/// The "PKCS5 PBKDF2 HMAC" algorithm will be used to generate the key.
	/// The `iterations` parameter should generally be a number greater than 1000.
	/// The `keyLength` parameter should indicate the desired key length and will generally match the `keyLength` of a cipher.
	public func deriveKey(password: [UInt8], salt: [UInt8], iterations: Int, keyLength: Int) -> [UInt8]? {
		return password.withUnsafeBytes { password in
			salt.withUnsafeBytes { salt in
				deriveKey(password: password,
					salt: salt,
					iterations: iterations, keyLength: keyLength)
			}
		}
	}

	/// Derive a suitable encryption key based on a password and salt.
	/// The "PKCS5 PBKDF2 HMAC" algorithm will be used to generate the key.
	/// The `iterations` parameter should generally be a number greater than 1000.
	/// The `keyLength` parameter should indicate the desired key length and will generally match the `keyLength` of a cipher.
	public func deriveKey(password: UnsafeRawBufferPointer, salt: UnsafeRawBufferPointer, iterations: Int, keyLength: Int) -> [UInt8]? {
		guard let pw = password.baseAddress?.assumingMemoryBound(to: Int8.self),
			let sw = salt.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
			return nil
		}
		var a = [UInt8](repeating: 0, count: keyLength)
		guard 0 != PKCS5_PBKDF2_HMAC(pw, Int32(password.count),
		                  sw, Int32(salt.count),
		                  Int32(iterations), evp, Int32(keyLength),
		                  &a) else {
							return nil
		}
		return a
	}
}

extension Cipher {
	var evp: UnsafePointer<EVP_CIPHER> {
		switch self {
		case .des_ecb:			return EVP_des_ecb()
		case .des_ede:			return EVP_des_ede()
		case .des_ede3:			return EVP_des_ede3()
		case .des_ede_ecb:		return EVP_des_ede_ecb()
		case .des_ede3_ecb:		return EVP_des_ede3_ecb()
		case .des_cfb64:		return EVP_des_cfb64()
		case .des_cfb1:			return EVP_des_cfb1()
		case .des_cfb8:			return EVP_des_cfb8()
		case .des_ede_cfb64:	return EVP_des_ede_cfb64()
		case .des_ede3_cfb1:	return EVP_des_ede3_cfb1()
		case .des_ede3_cfb8:	return EVP_des_ede3_cfb8()
		case .des_ofb:			return EVP_des_ofb()
		case .des_ede_ofb:		return EVP_des_ede_ofb()
		case .des_ede3_ofb:		return EVP_des_ede3_ofb()
		case .des_cbc:			return EVP_des_cbc()
		case .des_ede_cbc:		return EVP_des_ede_cbc()
		case .des_ede3_cbc:		return EVP_des_ede3_cbc()
		case .desx_cbc:			return EVP_desx_cbc()
		case .des_ede3_wrap:	return EVP_des_ede3_wrap()
		case .rc4:				return EVP_rc4()
		case .rc4_40:			return EVP_rc4_40()
		case .rc4_hmac_md5:		return EVP_rc4_hmac_md5()
		case .rc2_ecb:			return EVP_rc2_ecb()
		case .rc2_cbc:			return EVP_rc2_cbc()
		case .rc2_40_cbc:		return EVP_rc2_40_cbc()
		case .rc2_64_cbc:		return EVP_rc2_64_cbc()
		case .rc2_cfb64:		return EVP_rc2_cfb64()
		case .rc2_ofb:			return EVP_rc2_ofb()
		case .bf_ecb:			return EVP_bf_ecb()
		case .bf_cbc:			return EVP_bf_cbc()
		case .bf_cfb64:			return EVP_bf_cfb64()
		case .bf_ofb:			return EVP_bf_ofb()
		case .cast5_ecb:		return EVP_cast5_ecb()
		case .cast5_cbc:		return EVP_cast5_cbc()
		case .cast5_cfb64:		return EVP_cast5_cfb64()
		case .cast5_ofb:		return EVP_cast5_ofb()
		case .aes_128_ecb:		return EVP_aes_128_ecb()
		case .aes_128_cbc:		return EVP_aes_128_cbc()
		case .aes_128_cfb1:		return EVP_aes_128_cfb1()
		case .aes_128_cfb8:		return EVP_aes_128_cfb8()
		case .aes_128_cfb128:	return EVP_aes_128_cfb128()
		case .aes_128_ofb:		return EVP_aes_128_ofb()
		case .aes_128_ctr:		return EVP_aes_128_ctr()
		case .aes_128_ccm:		return EVP_aes_128_ccm()
		case .aes_128_gcm:		return EVP_aes_128_gcm()
		case .aes_128_xts:		return EVP_aes_128_xts()
		case .aes_128_wrap:		return EVP_aes_128_wrap()
		case .aes_192_ecb:		return EVP_aes_192_ecb()
		case .aes_192_cbc:		return EVP_aes_192_cbc()
		case .aes_192_cfb1:		return EVP_aes_192_cfb1()
		case .aes_192_cfb8:		return EVP_aes_192_cfb8()
		case .aes_192_cfb128:	return EVP_aes_192_cfb128()
		case .aes_192_ofb:		return EVP_aes_192_ofb()
		case .aes_192_ctr:		return EVP_aes_192_ctr()
		case .aes_192_ccm:		return EVP_aes_192_ccm()
		case .aes_192_gcm:		return EVP_aes_192_gcm()
		case .aes_192_wrap:		return EVP_aes_192_wrap()
		case .aes_256_ecb:		return EVP_aes_256_ecb()
		case .aes_256_cbc:		return EVP_aes_256_cbc()
		case .aes_256_cfb1:		return EVP_aes_256_cfb1()
		case .aes_256_cfb8:		return EVP_aes_256_cfb8()
		case .aes_256_cfb128:	return EVP_aes_256_cfb128()
		case .aes_256_ofb:		return EVP_aes_256_ofb()
		case .aes_256_ctr:		return EVP_aes_256_ctr()
		case .aes_256_ccm:		return EVP_aes_256_ccm()
		case .aes_256_gcm:		return EVP_aes_256_gcm()
		case .aes_256_xts:		return EVP_aes_256_xts()
		case .aes_256_wrap:		return EVP_aes_256_wrap()
		case .aes_128_cbc_hmac_sha1:		return EVP_aes_128_cbc_hmac_sha1()
		case .aes_256_cbc_hmac_sha1:		return EVP_aes_256_cbc_hmac_sha1()
		case .aes_128_cbc_hmac_sha256:	return EVP_aes_128_cbc_hmac_sha256()
		case .aes_256_cbc_hmac_sha256:	return EVP_aes_256_cbc_hmac_sha256()
		case .camellia_128_ecb:			return EVP_camellia_128_ecb()
		case .camellia_128_cbc:			return EVP_camellia_128_cbc()
		case .camellia_128_cfb1:		return EVP_camellia_128_cfb1()
		case .camellia_128_cfb8:		return EVP_camellia_128_cfb8()
		case .camellia_128_cfb128:		return EVP_camellia_128_cfb128()
		case .camellia_128_ofb:			return EVP_camellia_128_ofb()
		case .camellia_192_ecb:			return EVP_camellia_192_ecb()
		case .camellia_192_cbc:			return EVP_camellia_192_cbc()
		case .camellia_192_cfb1:		return EVP_camellia_192_cfb1()
		case .camellia_192_cfb8:		return EVP_camellia_192_cfb8()
		case .camellia_192_cfb128:		return EVP_camellia_192_cfb128()
		case .camellia_192_ofb:			return EVP_camellia_192_ofb()
		case .camellia_256_ecb:			return EVP_camellia_256_ecb()
		case .camellia_256_cbc:			return EVP_camellia_256_cbc()
		case .camellia_256_cfb1:		return EVP_camellia_256_cfb1()
		case .camellia_256_cfb8:		return EVP_camellia_256_cfb8()
		case .camellia_256_cfb128:		return EVP_camellia_256_cfb128()
		case .camellia_256_ofb:			return EVP_camellia_256_ofb()
		case .seed_ecb:			return EVP_seed_ecb()
		case .seed_cbc:			return EVP_seed_cbc()
		case .seed_cfb128:		return EVP_seed_cfb128()
		case .seed_ofb:			return EVP_seed_ofb()
		case .custom(let name):	  return EVP_get_cipherbyname(name)
		}
	}

	public var blockSize: Int {
		return Int(copenssl_EVP_CIPHER_block_size(evp))
	}

	public var keyLength: Int {
		return Int(copenssl_EVP_CIPHER_key_length(evp))
	}

	public var ivLength: Int {
		return Int(copenssl_EVP_CIPHER_iv_length(evp))
	}

	func encryptLength(sourceCount l: Int) -> Int {
		return l + (self.blockSize - l % self.blockSize)
	}

	func decryptLength(sourceCount l: Int) -> Int {
		return l
	}

	func encrypt(_ data: UnsafeRawBufferPointer, key: UnsafeRawBufferPointer, iv: UnsafeRawBufferPointer) -> UnsafeMutableRawBufferPointer? {
		guard let ctx = EVP_CIPHER_CTX_new(),
			let keyBase = key.baseAddress,
			let ivBase = iv.baseAddress else {
			return nil
		}
		defer {
			EVP_CIPHER_CTX_free(ctx)
		}
		guard 1 == EVP_EncryptInit_ex(ctx, self.evp, nil,
		                              keyBase.assumingMemoryBound(to: UInt8.self),
		                              ivBase.assumingMemoryBound(to: UInt8.self)) else {
			return nil
		}
		let allocLength = encryptLength(sourceCount: data.count)
		let dstPtr = UnsafeMutableRawBufferPointer.allocate(byteCount: allocLength, alignment: 0)
		var wroteLength = Int32(0)
		guard 1 == EVP_EncryptUpdate(ctx,
		                             dstPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
		                             &wroteLength,
		                             data.baseAddress?.assumingMemoryBound(to: UInt8.self),
		                             Int32(data.count)) else {
			dstPtr.deallocate()
			return nil
		}
		let owroteLength = Int(wroteLength)
		guard 1 == EVP_EncryptFinal(ctx,
		                            dstPtr.baseAddress?.assumingMemoryBound(to: UInt8.self).advanced(by: Int(wroteLength)),
		                            &wroteLength) else {
			dstPtr.deallocate()
			return nil
		}
		let iwroteLength = Int(wroteLength) + owroteLength
		if iwroteLength < allocLength {
			let newDstPtr = UnsafeMutableRawBufferPointer.allocate(byteCount: iwroteLength, alignment: 0)
			memcpy(newDstPtr.baseAddress!, dstPtr.baseAddress!, iwroteLength)
			dstPtr.deallocate()
			return newDstPtr
		}
		return dstPtr
	}

	func decrypt(_ data: UnsafeRawBufferPointer, key: UnsafeRawBufferPointer, iv: UnsafeRawBufferPointer) -> UnsafeMutableRawBufferPointer? {
		guard let ctx = EVP_CIPHER_CTX_new(),
			let keyBase = key.baseAddress,
			let ivBase = iv.baseAddress else {
				return nil
		}
		defer {
			EVP_CIPHER_CTX_free(ctx)
		}
		guard 1 == EVP_DecryptInit_ex(ctx, self.evp, nil,
		                              keyBase.assumingMemoryBound(to: UInt8.self),
		                              ivBase.assumingMemoryBound(to: UInt8.self)) else {
										return nil
		}
		let allocLength = decryptLength(sourceCount: data.count)
		let dstPtr = UnsafeMutableRawBufferPointer.allocate(byteCount: allocLength, alignment: 0)
		var wroteLength = Int32(0)
		guard 1 == EVP_DecryptUpdate(ctx,
		                             dstPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
		                             &wroteLength,
		                             data.baseAddress?.assumingMemoryBound(to: UInt8.self),
		                             Int32(data.count)) else {
										dstPtr.deallocate()
										return nil
		}
		let owroteLength = Int(wroteLength)
		guard 1 == EVP_DecryptFinal(ctx,
		                            dstPtr.baseAddress?.assumingMemoryBound(to: UInt8.self).advanced(by: Int(wroteLength)),
		                            &wroteLength) else {
										dstPtr.deallocate()
										return nil
		}
		let iwroteLength = Int(wroteLength) + owroteLength
		if iwroteLength < allocLength {
			let newDstPtr = UnsafeMutableRawBufferPointer.allocate(byteCount: iwroteLength, alignment: 0)
			memcpy(newDstPtr.baseAddress!, dstPtr.baseAddress!, iwroteLength)
			dstPtr.deallocate()
			return newDstPtr
		}
		return dstPtr
	}

	func encrypt(_ data: UnsafeRawBufferPointer,
	             password: UnsafeRawBufferPointer,
	             salt: UnsafeRawBufferPointer,
	             keyIterations: Int = 2048,
	             keyDigest: Digest = .md5) -> UnsafeMutableRawBufferPointer? {
		guard let derived = keyDigest.deriveKey(password: password,
		                                   salt: salt,
		                                   iterations: keyIterations,
		                                   keyLength: keyLength) else {
			return nil
		}
		let memBio = MemoryIO(data)
		guard let cms = derived.withUnsafeBytes({ CMS_EncryptedData_encrypt(memBio.bio, evp,
		                                          $0.baseAddress?.assumingMemoryBound(to: UInt8.self),
		                                          $0.count,
												  UInt32(CMS_STREAM|CMS_BINARY))}) else {
			return nil
		}
		defer {
			CMS_ContentInfo_free(cms)
		}
		let outBio = MemoryIO()
		guard 0 != PEM_write_bio_CMS_stream(outBio.bio, cms, memBio.bio, Int32(CMS_STREAM|CMS_BINARY)),
				let mem = outBio.memory else {
			return nil
		}
		let ret = UnsafeMutableRawBufferPointer.allocate(byteCount: mem.count, alignment: 0)
		guard let r = ret.baseAddress, let m = mem.baseAddress else {
			ret.deallocate()
			return nil
		}
		memcpy(r, m, mem.count)
		return ret
	}

	func decrypt(_ data: UnsafeRawBufferPointer, password: UnsafeRawBufferPointer, salt: UnsafeRawBufferPointer, keyIterations: Int = 2048, keyDigest: Digest = .md5) -> UnsafeMutableRawBufferPointer? {
		let memBio = MemoryIO(data)
		guard let cms = PEM_read_bio_CMS(memBio.bio, nil, nil, nil) else {
			return nil
		}
		defer {
			CMS_ContentInfo_free(cms)
		}
		let outBio = MemoryIO()
		do {
			guard let derived = keyDigest.deriveKey(password: password,
													salt: salt,
													iterations: keyIterations,
													keyLength: keyLength) else {
				return nil
			}
			let cres = derived.withUnsafeBytes { derivedPassword -> Int32 in
				return CMS_EncryptedData_decrypt(cms,
								derivedPassword.baseAddress?.assumingMemoryBound(to: UInt8.self),
								derivedPassword.count,
								nil, outBio.bio, UInt32(CMS_STREAM|CMS_BINARY))
			}
			guard 0 != cres else {
				return nil
			}
		}
		guard let mem = outBio.memory, !mem.isEmpty else {
			return nil
		}
		let ret = UnsafeMutableRawBufferPointer.allocate(byteCount: mem.count, alignment: 0)
		guard let r = ret.baseAddress, let m = mem.baseAddress else {
			ret.deallocate()
			return nil
		}
		memcpy(r, m, mem.count)
		return ret
	}
}
