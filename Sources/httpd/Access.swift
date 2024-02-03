import Foundation
import PerfectCRUD

struct Access: Codable {
    public let id: UUID
    public let code: UUID
    public let createdAt: Int
    public let lastAttempt: Int
    public static let validResetSeconds = Settings.default.validResetSeconds
    public static let validAttemptSeconds = Settings.default.validAttemptSeconds
    public static let table = Settings.default.db.table(Self.self)
    init(id i: UUID, code cd: UUID = UUID(), createdAt cat: Int = Date().timestamp, lastAttempt att: Int = Date().timestamp) {
        id = i; code = cd; lastAttempt = att; createdAt = cat
    }
    func delete() throws {
        try Self.table.where(\Self.id == id).delete()
    }
    public static func lookup(id: UUID) throws -> Access? {
        let records = try Self.table.where(\Self.id == id).select().map { $0 }
        return records.first
    }
    public static func recover(code: UUID) throws -> UUID {
        let records = try Self.table.where(\Self.code == code).select().map { $0 }
        guard let access = records.first else {
            throw Exception.invalidCode
        }
        let now = Date().timestamp
        guard now < access.createdAt + validResetSeconds else {
            try access.delete()
            throw Exception.expired
        }
        return access.id
    }
    public static func reset(id: UUID) throws -> UUID {
        let now = Date().timestamp
        let rec: Access
        if let access = try lookup(id: id) {
            if now > access.createdAt + Self.validResetSeconds {
                try access.delete()
                let record = Self.init(id: id)
                try table.insert(record)
                rec = record
            } else if now < access.lastAttempt + validAttemptSeconds {
                throw Exception.tooManyAttempts
            } else {
                let updated = Self.init(id: id, code: access.code, createdAt: access.createdAt, lastAttempt: now)
                try table.update(updated)
                rec = updated
            }
        } else {
            let record = Self.init(id: id)
            try table.insert(record)
            rec = record
        }
        return rec.code
    }
}
