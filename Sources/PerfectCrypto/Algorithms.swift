//
//  Algorithms.swift
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

/// Available encoding methods.
public enum Encoding {
	case base64
	case base64url
	case hex
}

/// Available digest methods.
public enum Digest {
	case md4
	case md5
	case sha1
	case sha224
	case sha256
	case sha384
	case sha512
	case ripemd160
	case whirlpool
	case custom(String)
}

/// Available ciphers.
public enum Cipher {
	case des_ecb
	case des_ede
	case des_ede3
	case des_ede_ecb
	case des_ede3_ecb
	case des_cfb64
	case des_cfb1
	case des_cfb8
	case des_ede_cfb64
	case des_ede3_cfb1
	case des_ede3_cfb8
	case des_ofb
	case des_ede_ofb
	case des_ede3_ofb
	case des_cbc
	case des_ede_cbc
	case des_ede3_cbc
	case desx_cbc
	case des_ede3_wrap
	case rc4
	case rc4_40
	case rc4_hmac_md5
	case rc2_ecb
	case rc2_cbc
	case rc2_40_cbc
	case rc2_64_cbc
	case rc2_cfb64
	case rc2_ofb
	case bf_ecb
	case bf_cbc
	case bf_cfb64
	case bf_ofb
	case cast5_ecb
	case cast5_cbc
	case cast5_cfb64
	case cast5_ofb
	case aes_128_ecb
	case aes_128_cbc
	case aes_128_cfb1
	case aes_128_cfb8
	case aes_128_cfb128
	case aes_128_ofb
	case aes_128_ctr
	case aes_128_ccm
	case aes_128_gcm
	case aes_128_xts
	case aes_128_wrap
	case aes_192_ecb
	case aes_192_cbc
	case aes_192_cfb1
	case aes_192_cfb8
	case aes_192_cfb128
	case aes_192_ofb
	case aes_192_ctr
	case aes_192_ccm
	case aes_192_gcm
	case aes_192_wrap
	case aes_256_ecb
	case aes_256_cbc
	case aes_256_cfb1
	case aes_256_cfb8
	case aes_256_cfb128
	case aes_256_ofb
	case aes_256_ctr
	case aes_256_ccm
	case aes_256_gcm
	case aes_256_xts
	case aes_256_wrap
	case aes_128_cbc_hmac_sha1
	case aes_256_cbc_hmac_sha1
	case aes_128_cbc_hmac_sha256
	case aes_256_cbc_hmac_sha256
	case camellia_128_ecb
	case camellia_128_cbc
	case camellia_128_cfb1
	case camellia_128_cfb8
	case camellia_128_cfb128
	case camellia_128_ofb
	case camellia_192_ecb
	case camellia_192_cbc
	case camellia_192_cfb1
	case camellia_192_cfb8
	case camellia_192_cfb128
	case camellia_192_ofb
	case camellia_256_ecb
	case camellia_256_cbc
	case camellia_256_cfb1
	case camellia_256_cfb8
	case camellia_256_cfb128
	case camellia_256_ofb
	case seed_ecb
	case seed_cbc
	case seed_cfb128
	case seed_ofb
	case custom(String)
}
