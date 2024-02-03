import Foundation
import PerfectHTTP

public enum Exception: Error {
    case accountExists
    case accountLocked
    case expired
    case invalidAccount
    case invalidAuthority
    case invalidCode
    case invalidContent
    case invalidDatabase
    case invalidJSON
    case invalidJWT
    case invalidMIME
    case invalidPassword
    case invalidSettingsPath
    case ok
    case tooManyAttempts
}

public extension Error {
    var jsonString: String {
        return "{\n\t\"error\": \"\(self)\"\n}\n"
    }
}
