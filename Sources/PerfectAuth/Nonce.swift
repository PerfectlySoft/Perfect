//
//  Nonce.swift
//  
//
//  Created by Rockford Wei on 2022-06-27.
//

import Foundation
import PerfectCrypto

/// Nonce is a special server allocated JWT which can be typically used to check if a post is valid.
/// For example, any post method should include a valid nonce before action, so if not, the server can just simply ignore it.
public struct Nonce {
    fileprivate struct Payload: Codable {
        let host: UUID
        let timestamp: TimeInterval
        init(host h: UUID, timestamp t: TimeInterval = Date().timeIntervalSince1970) {
            host = h; timestamp = t
        }
    }

    fileprivate static let algo = JWT.Alg.hs256
    fileprivate static let host = UUID()

    /// allocate a nonce string
    public static func allocate(authorityPrivateKey: PEMKey) throws -> String {
        let payload = Payload(host: host)
        return try JWTCreator(payload: payload).sign(alg: algo, key: authorityPrivateKey)
    }

    /// check if this nonce is valid
    public static func validate(nonce: String, seconds: Int = 900, authorityPublicKey: PEMKey) throws {
        // swiftlint:disable type_name
        typealias exception = AuthenticationTokenClaim.Exception
        guard let jwt = JWTVerifier(nonce) else {
            throw exception.invalidJsonWebToken
        }
        try jwt.verify(algo: algo, key: authorityPublicKey)
        let payload = try jwt.decode(as: Payload.self)
        guard payload.host == host else {
            throw exception.invalidHostKey
        }
        guard payload.timestamp + TimeInterval(seconds) > Date().timeIntervalSince1970 else {
            throw exception.expired
        }
    }
}
