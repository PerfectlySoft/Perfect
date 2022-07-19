//
//  Transient.swift
//  
//
//  Created by Rockford Wei on 2022-07-12.
//

import Foundation
import PerfectCRUD
import PerfectSQLite

public struct OneTimeRecord: Codable {
    let id: Int
    let subject: String
    let createdAt: Int
    init(id i: Int = Int.random(in: 0..<1_000_000), subject s: String, createdAt c: Int = Date().timestamp) {
        id = i; subject = s; createdAt = c
    }
}

public final class Transient {
    public enum Exception: Error {
        case overAttempted(shouldWaitSeconds: Int)
        case subjectNotFound
        case invalidCode
        case expired
    }
    public static let minimalRetrySeconds = 60
    public static let expirySeconds = 900 // 15 minutes
    public static let dbPath = "/tmp/perfect-transient.sqlite3"
    private static let queue = DispatchQueue(label: UUID().uuidString)
    private static let db: Database<SQLiteDatabaseConfiguration> = {
        do {
            let config = try SQLiteDatabaseConfiguration(dbPath)
            let db = Database(configuration: config)
            try db.create(OneTimeRecord.self, policy: .reconcileTable)
            return db
        } catch {
            fatalError("unable load \(dbPath) for transient code control because \(error)")
        }
    }()
    public static func cleanup(expiry: Int = expirySeconds) {
        do {
            let expired = Date().timestamp - expiry
            let table = db.table(OneTimeRecord.self)
            try table.where(\OneTimeRecord.createdAt <= expired).delete()
            queue.asyncAfter(deadline: .now() + Double(expiry)) {
                #if DEBUG
                CRUDLogging.log(.info, "\(expired):: cleaning up obsolete records")
                #endif
                cleanup(expiry: expiry)
            }
        } catch {
            CRUDLogging.log(.warning, "unable to clean the transient allocator because \(error)")
        }
    }
    public static func record(of subject: String) throws -> OneTimeRecord? {
        let table = db.table(OneTimeRecord.self)
        return try table.order(descending: \OneTimeRecord.createdAt)
            .where(\OneTimeRecord.subject == subject)
            .first()
    }
    public static func allocate(subject: String, minimalRetry: Int = minimalRetrySeconds) throws -> Int {
        let table = db.table(OneTimeRecord.self)
        if let record = try record(of: subject) {
            let secondsToWait = minimalRetry - (Date().timestamp - record.createdAt)
            if  secondsToWait > 0 {
                throw Exception.overAttempted(shouldWaitSeconds: secondsToWait)
            } else {
                try table.where(\OneTimeRecord.subject == subject).delete()
            }
        }
        let record = OneTimeRecord(subject: subject)
        try table.insert(record)
        return record.id
    }
    public static func validate(id: Int, subject: String, expiry: Int = expirySeconds) throws {
        guard let record = try record(of: subject) else {
            throw Exception.subjectNotFound
        }
        guard id == record.id else {
            throw Exception.invalidCode
        }
        guard Date().timestamp < record.createdAt + expiry else {
            throw Exception.expired
        }
    }
}
