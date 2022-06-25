//
//  Based on SAuth.swift & Codables.swift
//  [SAuthLib](https://github.com/kjessup/SAuthLib)
//  [SAuthCodables](https://github.com/kjessup/SAuthCodables)
//
//  Created by Kyle Jessup on 2018-02-26.
//  Digested by Rockford Wei on 2022-06-23.
//

import Foundation
import PerfectCrypto

// swiftlint:disable line_length
public struct AuthenticationTokenClaim {
    public enum Keys {
        public static let account = "acc"
        public static let expiration = "exp"
        public static let issuedAt = "iat"
        public static let issuer = "iss"
        public static let subject = "sub"
    }
    public enum Exception: Error {
        case invalidJsonWebToken
    }
    public let payload: [String: Any]
    public var account: String? {
        payload[Keys.account] as? String
    }
    public var expiration: Int? {
        payload[Keys.expiration] as? Int
    }
    public var issuer: String? {
        payload[Keys.issuer] as? String
    }
    public var issuedAt: Int? {
        payload[Keys.issuedAt] as? Int
    }
    public var subject: String? {
        payload[Keys.subject] as? String
    }
    public init(fields: [String: Any]) {
        var fields = fields
        self.init(account: fields.removeValue(forKey: Keys.account) as? String, expiration: fields.removeValue(forKey: Keys.expiration) as? Int, issuer: fields.removeValue(forKey: Keys.issuer) as? String, issuedAt: fields.removeValue(forKey: Keys.issuedAt) as? Int, subject: fields.removeValue(forKey: Keys.subject) as? String, extra: fields)
    }
    public init(account: String? = nil, expiration: Int? = nil, issuer: String? = nil, issuedAt: Int? = nil, subject: String? = nil, extra: [String: Any]? = nil) {
        var p: [String: Any] = [:]
        if let v = account {
            p[Keys.account] = v
        }
        if let v = expiration {
            p[Keys.expiration] = v
        }
        if let v = issuer {
            p[Keys.issuer] = v
        }
        if let v = issuedAt {
            p[Keys.issuedAt] = v
        }
        if let v = subject {
            p[Keys.subject] = v
        }
        if let v = extra {
            p.merge(v, uniquingKeysWith: { $1 })
        }
        payload = p
    }
    public static let algo = JWT.Alg.rs256
    public init(jsonWebToken: String, authorityPublicKey: PEMKey) throws {
        guard let jwt = JWTVerifier(jsonWebToken) else {
            throw Exception.invalidJsonWebToken
        }
        try jwt.verify(algo: AuthenticationTokenClaim.algo, key: authorityPublicKey)
        self.init(fields: jwt.payload)
    }

    public func generateJsonWebToken(authorityPrivateKey: PEMKey) throws -> String? {
        return try JWTCreator(payload: payload)?.sign(alg: AuthenticationTokenClaim.algo, key: authorityPrivateKey)
    }
}

extension AuthenticationTokenClaim: Equatable {
    public static func == (lhs: AuthenticationTokenClaim, rhs: AuthenticationTokenClaim) -> Bool {
        return lhs.account == rhs.account && lhs.subject == rhs.subject && lhs.issuer == rhs.issuer && lhs.issuedAt == rhs.issuedAt && lhs.expiration == rhs.expiration
    }
}
