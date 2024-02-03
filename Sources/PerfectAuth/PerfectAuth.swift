//
//  Based on SAuth.swift
//  [SAuthLib](https://github.com/kjessup/SAuthLib)
//
//  Created by Kyle Jessup on 2018-02-26.
//  Digested by Rockford Wei on 2022-06-23.
//

import Foundation
import PerfectCrypto

open class AuthenticationUtilities {
    public static func hash(password: String) -> (hexSalt: String, hexHash: String)? {
        let saltBytes = Array<UInt8>(randomCount: 32)
        guard let saltHex = saltBytes.encode(.hex),
            let hashHex = hash(password: password, saltBytes: saltBytes) else {
                return nil
        }
        return (String(validatingUTF8: saltHex) ?? "", hashHex)
    }
    public static func validate(password: String, hexSalt: String, hexHash: String) -> Bool {
        guard let saltBytes = hexSalt.decode(.hex),
            let compareHexHash = hash(password: password, saltBytes: saltBytes) else {
                return false
        }
        return compareHexHash == hexHash
    }
    private static func hash(password: String, saltBytes: [UInt8]) -> String? {
        let pwBytes = Array(password.utf8)
        guard let hashBytes = Digest.sha256.deriveKey(password: pwBytes, salt: saltBytes, iterations: 2048, keyLength: 32),
            let hashHex = hashBytes.encode(.hex) else {
                return nil
        }
        return String(validatingUTF8: hashHex) ?? ""
    }
}
