import Foundation
import PerfectAuth
import PerfectCRUD
import PerfectSQLite

public enum AccountState: Int {
    case inactive = -1
    case signedUp = 0
    case verified = 1
}
public struct Account: Codable {
    public let id: UUID
    public let email: String
    public let mobile: String
    public let name: String
    public let status: Int
    public let admin: Int
    public let shadow: String
    public let salt: String
    public let createdAt: Int
    public let updatedAt: Int
    public static let validTokenSeconds = Settings.default.validTokenSeconds
    public static let table = Settings.default.db.table(Self.self)
    public static let scratchPadKey = "account"
    public var state: AccountState {
        return AccountState(rawValue: status) ?? .inactive
    }

    init(id i: UUID = UUID(),
         mobile m: String = "", email e: String, name n: String = "",
         status s: Int = AccountState.signedUp.rawValue,
         admin a: Int = 0, shadow hash: String = "", salt rnd: String = "",
         createdAt cat: Int = Date().timestamp,
         updatedAt upt: Int = Date().timestamp) {
        id = i; email = e; mobile = m; name = n; status = s
        admin = a; shadow = hash; salt = rnd
        createdAt = cat; updatedAt = upt
    }
    func save() throws -> Account {
        let record = try Self.table.where(\Self.id == id).count()
        let now = Date().timestamp
        if record > 0 {
            let updated = Account(id: id, mobile: mobile,
                                  email: email, name: name,
                                  status: status, admin: admin,
                                  shadow: shadow, salt: salt,
                                  createdAt: createdAt, updatedAt: now)
            try Self.table.update(updated)
            return updated
        } else {
            let newRecord = Account(id: id, mobile: mobile,
                                    email: email, name: name,
                                    status: status, admin: admin,
                                    shadow: shadow, salt: salt,
                                    createdAt: now, updatedAt: now)
            try Self.table.insert(newRecord)
            return newRecord
        }
    }
    func delete() throws {
        try Self.table.where(\Self.id == id).delete()
    }

    public static func lookup(id: UUID) throws -> Account? {
        let records = try Self.table.where(\Self.id == id).select().map { $0 }
        return records.first
    }
    public static func find(email: String) throws -> Account? {
        let records = try Self.table.where(\Self.email == email).select().map { $0 }
        return records.first
    }

    public static func signUp(email: String, mobile: String = "", name: String = "anonymous", password: String) throws -> Account? {
        guard let _ = try find(email: email) else {
            throw Exception.accountExists
        }
        guard let hashed = AuthenticationUtilities.hash(password: password) else {
            throw Exception.invalidPassword
        }
        let account = Account(mobile: mobile, email: email, name: name, shadow: hashed.hexHash, salt: hashed.hexSalt)
        return try account.save()
    }
    public static func signIn(email: String, password: String) throws -> Account {
        guard let account = try find(email: email) else {
            throw Exception.invalidAccount
        }
        guard account.state != .inactive else {
            throw Exception.accountLocked
        }
        guard AuthenticationUtilities.validate(password: password, hexSalt: account.salt, hexHash: account.shadow) else {
            throw Exception.invalidPassword
        }
        return account
    }

    private func claim() -> AuthenticationTokenClaim {
        let now = Date().timestamp
        return AuthenticationTokenClaim(account: id.uuidString.lowercased(), expiration: now + Self.validTokenSeconds, issuer: Settings.default.name, issuedAt: now, subject: email, extra: nil)
    }

    public func claimJWT() throws -> String {
        guard let token = try claim().generateJsonWebToken(authorityPrivateKey: Settings.default.keyPrivate) else {
            throw Exception.invalidJWT
        }
        return token
    }

    public static func load(jsonWebToken: String) throws -> Account {
        let claim = try AuthenticationTokenClaim(jsonWebToken: jsonWebToken, authorityPublicKey: Settings.default.keyPublic)
        guard claim.issuer == Settings.default.name else {
            throw Exception.invalidAuthority
        }
        guard let exp = claim.expiration, exp > Date().timestamp + Self.validTokenSeconds else {
            throw Exception.expired
        }
        guard let acc = claim.account, let email = claim.subject, let id = UUID(uuidString: acc), let account = try lookup(id: id), account.email == email else {
            throw Exception.invalidAccount
        }
        return account
    }

    public static func requestPasswordReset(email: String) throws -> UUID {
        guard let account = try find(email: email) else {
            throw Exception.invalidAccount
        }
        guard account.state != .inactive else {
            throw Exception.accountLocked
        }
        return try Access.reset(id: account.id)
    }

    public static func resetPassword(code: UUID, password: String) throws -> Account {
        let id = try Access.recover(code: code)
        guard let acc = try lookup(id: id) else {
            throw Exception.invalidAccount
        }
        guard acc.state != .inactive else {
            throw Exception.accountLocked
        }
        guard let hashed = AuthenticationUtilities.hash(password: password) else {
            throw Exception.invalidPassword
        }
        let account = Account(id: acc.id, mobile: acc.mobile, email: acc.email, name: acc.name, shadow: hashed.hexHash, salt: hashed.hexSalt, createdAt: acc.createdAt, updatedAt: Date().timestamp)
        return try account.save()
    }
}
