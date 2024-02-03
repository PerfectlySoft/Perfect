import Foundation
import PerfectCRUD
import PerfectCrypto
import PerfectLib
import PerfectSQLite

public struct Settings: Codable {
    public let binding: String
    public let email: String
    public let name: String
    public let pathDB: String
    public let pathKeyPublic: String
    public let pathKeyPrivate: String
    public let pathTemplates: String
    public let pathWebroot: String
    public let port: Int
    public let smtpServerUrl: String
    public let smtpUsername: String
    public let smtpPassword: String
    public let url: String
    public let validAttemptSeconds: Int
    public let validResetSeconds: Int
    public let validTokenSeconds: Int

    private static var _keyPrivate: PEMKey?
    private static var _keyPublic: PEMKey?
    private static var _db: Database<SQLiteDatabaseConfiguration>?

    init(binding b: String = "0.0.0.0", email e: String,
         name n: String = "localhost", pathDB pdb: String = "db.sqlite3",
         pathKeyPublic pub: String = "public.pem", pathKeyPrivate prv: String = "private.pem",
         pathTemplates tmp: String = "templates", pathWWW web: String = "webroot", port p: Int = 8080,
         smtpServerUrl surl: String, smtpUsername susr: String, smtpPassword spwd: String, url u: String,
         validAttemptSeconds vas: Int = 60, validResetSeconds vrs: Int = 600,
         validTokenSeconds vts: Int = 7200) {
        let www = File(web)
        guard www.exists && www.isDir else {
            fatalError("unable to locate web root folder \(web)")
        }
        do {
            Self._keyPrivate = try PEMKey(pemPath: prv)
        } catch {
            fatalError("unable to load private key \(prv) because `\(error)`\nuse `openssl genrsa -out \(prv) 1024` to generate a new one")
        }
        do {
            Self._keyPublic = try PEMKey(pemPath: pub)
        } catch {
            fatalError("unable to load public key \(pub) because `\(error)`\nuse `openssl rsa -in \(prv) -out \(pub) -pubout -outform PEM` to generate the public key.")
        }
        do {
            let config = try SQLiteDatabaseConfiguration(pdb)
            let db = Database(configuration: config)
            try db.create(Account.self)
            try db.create(Access.self)
            Self._db = db
        } catch {
            fatalError("unable to load database configuration from \(pdb) because \(error)")
        }
        binding = b; email = e; name = n; pathDB = pdb
        pathKeyPublic = pub; pathKeyPrivate = prv; pathTemplates = tmp; pathWebroot = web
        smtpServerUrl = surl; smtpUsername = susr; smtpPassword = spwd; url = u
        port = p; validAttemptSeconds = vas; validResetSeconds = vrs; validTokenSeconds = vts
    }
    init(path: String) throws {
        let url = URL(fileURLWithPath: path)
        let data = try Data(contentsOf: url)
        let s = try JSONDecoder().decode(Self.self, from: data)
        self.init(binding: s.binding, email: s.email,
                  name: s.name, pathDB: s.pathDB,
                  pathKeyPublic: s.pathKeyPublic, pathKeyPrivate: s.pathKeyPrivate,
                  pathTemplates: s.pathTemplates, pathWWW: s.pathWebroot, port: s.port,
                  smtpServerUrl: s.smtpServerUrl,
                  smtpUsername: s.smtpUsername,
                  smtpPassword: s.smtpPassword,
                  url: s.url,
                  validAttemptSeconds: s.validAttemptSeconds,
                  validResetSeconds: s.validResetSeconds,
                  validTokenSeconds: s.validTokenSeconds)
    }
    public static let path = "./settings.json"
    public static let `default`: Self = {
        do {
            return try Self(path: Self.path)
        } catch {
            fatalError("unable to load settings file \(Self.path) because `\(error)`")
        }
    }()
    public var keyPublic: PEMKey {
        guard let key = Self._keyPublic else {
            fatalError("general fault: unable to load public key")
        }
        return key
    }
    public var keyPrivate: PEMKey {
        guard let key = Self._keyPrivate else {
            fatalError("general fault: unable to load private key")
        }
        return key
    }
    public var json: String {
        let errorCoding = "{\"error\": \"invalid json encoding\"}"
        guard let data = try? JSONEncoder().encode(self) else {
            return errorCoding
        }
        return String(data: data, encoding: .utf8) ?? errorCoding
    }

    public var db: Database<SQLiteDatabaseConfiguration> {
        guard let db = Self._db else {
            fatalError("general fault: unable to open database")
        }
        return db
    }
}
