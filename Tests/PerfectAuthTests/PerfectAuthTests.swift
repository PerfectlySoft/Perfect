import Foundation
import PerfectLib
import PerfectCrypto
import XCTest

@testable import PerfectAuth

// swiftlint:disable line_length
class PerfectAuthTests: XCTestCase {

    func testOneTimeCode() throws {
        File(Transient.dbPath).delete()
        let subject = "800-000-1111"
        let expiry = 3
        var code = try Transient.allocate(subject: subject, minimalRetry: expiry)
        XCTAssertTrue(code >= 0 && code < 1_000_000)
        do {
            _ = try Transient.allocate(subject: subject, minimalRetry: expiry)
        } catch Transient.Exception.overAttempted(let secondsToWait) {
            print("over attempt caught: \(secondsToWait) seconds")
        }
        try Transient.validate(id: code, subject: subject)
        do {
            try Transient.validate(id: code, subject: "")
        } catch Transient.Exception.subjectNotFound {
            print("invalid subject caught")
        }
        do {
            try Transient.validate(id: -1, subject: subject)
        } catch Transient.Exception.invalidCode {
            print("invalid code caught")
        }
        sleep(UInt32(expiry + 1))
        do {
            try Transient.validate(id: code, subject: subject, expiry: expiry)
        } catch Transient.Exception.expired {
            print("expiration caught")
        }
        Transient.cleanup(expiry: expiry)
        code = try Transient.allocate(subject: subject, minimalRetry: expiry)
        XCTAssertTrue(code >= 0 && code < 1_000_000)
        sleep(UInt32(expiry) + 1)
        XCTAssertNil(try Transient.record(of: subject))
    }

	func testPasswordUtilities() throws {
        let password = UUID().uuidString.lowercased()
        guard let hash = AuthenticationUtilities.hash(password: password) else {
            XCTFail("unable to hash password \(password)")
            return
        }
        let result = AuthenticationUtilities.validate(password: password, hexSalt: hash.hexSalt, hexHash: hash.hexHash)
        print("password", password)
        print("salt", hash.hexSalt)
        print("hash", hash.hexHash)
        XCTAssertTrue(result)
	}

    func testJWT() throws {
        let now = Int(Date().timeIntervalSince1970)
        let exp = now + 3600
        let ath = "perfect"
        let acc = UUID().uuidString.lowercased()
        let sub = "abc@def.ghi"
        let tokenClaimed = AuthenticationTokenClaim(account: acc, expiration: exp, issuer: ath, issuedAt: now, subject: sub)
        let key0 = try PEMKey(source: privKey)
        guard let jwt = try tokenClaimed.generateJsonWebToken(authorityPrivateKey: key0)
        else {
            XCTFail("unable to generate JWT")
            return
        }
        let key1 = try PEMKey(source: pubKey)
        let attempt = try AuthenticationTokenClaim(jsonWebToken: jwt, authorityPublicKey: key1)
        XCTAssertEqual(tokenClaimed, attempt)
    }

    let pubKey = "-----BEGIN CERTIFICATE-----\nMIIDNDCCAhwCCQDH2QBnQs6n6DANBgkqhkiG9w0BAQUFADBcMQswCQYDVQQGEwJB\nVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0\ncyBQdHkgTHRkMRUwEwYDVQQDEwxiYWR0aGluZy5vcmcwHhcNMTcwOTIyMTY0MDI0\nWhcNMTcxMDIyMTY0MDI0WjBcMQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1T\ndGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMRUwEwYDVQQD\nEwxiYWR0aGluZy5vcmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCk\n9+U38uJNgz80opuSLPB9RAMMYzLA10E7Ix0Ge2FI5VVRWR5GItDH3h7fxH8kLyZ+\nX1Qovq4NSXLUIQv6kR+OXhyDa1Q8MYwr9s8UNN24QFBoPGvj06aKfu+u3Kt1ezFD\nea2/DRB5WMFZmKO37LNYUJQZs7/NFFltpt7m0Q3tewYdnzMfChRgzcfKT3I21KMU\nrPACysMInijoWNA93e1cIGpIUT9oNNrTHKQ18VWJjf2DGTlRDw+Lc1AoMtUCjyGQ\nFZ3zyzkt1DvUuu+g+lhTol2ffBx/vMlC9K9Nh+y1O7zddHQhcpM/alcL5o+R5Jnp\nXd3AfO+OYQF2ZN3gBZhdAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAHixAUQ22cpv\n9MKNyaTeiReNeipL1UKDCE/PDIg15WdNjzjcEbZAYqEdga4VnLcxDeV/OsvJDz/r\nioQiZgNTog0f15Q9USi5g1KtZrwParTitfRS/Uh9gjj+cbDj/M/WcIEiCHwMl2Mv\neOMYtyL/asdUQiVJBMvUggU4PDRtVjA+uVKvvv9brcJb+yBy9kSazem4olPGJCz4\nPxqAOUQ6KhQyuhKfLc7qIAej8NGXw5K7fG1e2Gx9etNM8lUZRM2Klo/0rZ5iqiq7\nuI5korDYLIAOXOPRvfP3B3mIakZtg++SnDCgVpU2LdEx9V5eov4qij8VAORS8g9o\nuaXv2Q++efc=\n-----END CERTIFICATE-----\n"
    let privKey = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEApPflN/LiTYM/NKKbkizwfUQDDGMywNdBOyMdBnthSOVVUVke\nRiLQx94e38R/JC8mfl9UKL6uDUly1CEL+pEfjl4cg2tUPDGMK/bPFDTduEBQaDxr\n49Omin7vrtyrdXsxQ3mtvw0QeVjBWZijt+yzWFCUGbO/zRRZbabe5tEN7XsGHZ8z\nHwoUYM3Hyk9yNtSjFKzwAsrDCJ4o6FjQPd3tXCBqSFE/aDTa0xykNfFViY39gxk5\nUQ8Pi3NQKDLVAo8hkBWd88s5LdQ71LrvoPpYU6Jdn3wcf7zJQvSvTYfstTu83XR0\nIXKTP2pXC+aPkeSZ6V3dwHzvjmEBdmTd4AWYXQIDAQABAoIBAEM9Jxhezw546FIz\n1OUHnB3ykquB4zXmhpfr//CcaVKk5tl5UXWUyzQrvLnIBWpiLXZktJDG53pS7ZK4\nxYEjlZEZmtWV8Yd3SoLA3jaGNbjbveo+dlst8TuR8W98UgZYaAPwnHi6gnRzUJuM\nM27L822TqkmvkgWsvaaL1V6O5vZb/sdB1+2vV0uE6kKX0gXoCmkwSc/an7a5tY/O\njLl/AZ/P0yJOnCaEZvkpvauP4lK7tNjl078pn3D3scBumL3/mpAtCDB7uPuC8LZn\nWh6pxgNSE9cCpP96EBQbUskgNqG9k5TCtVO8kaCmuV4aPDLWVELuLuryCDsjAWmD\n/PqMV6ECgYEA1SuPcoLoH/DOA+QL2sXmMzeOY2tKZ39UXoqoGM0Y7WaxIvmF/Uv2\nY7BrEpjwsSATFEDzx7Hfds1iBLdO6yb/3z/ajHpEdXu74Efx5HhHSxwi3JaxqLqx\n1nzHfR6qMeSNuGQpVdQpQKnwVDUipgNIcEDkseIj2MVfiXNtBf7D6psCgYEAxh0R\nN4dwVxV9EJLnd5F/CGyyHAoUfMxIrRBKjJTr/qqq+dnbJMX8PzCkAmuS8r5Lr8nn\nER+iAExf7oQhi27qVlOICoWGrHjcqwsi5Tn9TLokbbQCOrUHHn5N8dCIoPVw3Fpp\ndaS/ko2ThdI1DgDS1jq8UPdBrJ/02fO8XK+P3GcCgYA2Vs5QQHJvgfDiKQWklQHj\nWGwhh74Ft/2HxAyplc6e5aiN49F2CiEatGP276mbXTO/2/bIlt0B6cTsstWZN+3N\nuPc7DAfbctkniO9ucAKscNWqKXfMLRscM96eVGzKHxrJQC8RQ+3oH+m1bX4Rl5Cl\nnMUvWxgML/P0k8nc116VtQKBgClPsmFj6rceEgA8weua+WRmVhWmvHLxnk4IUaNT\nAosOR6zmEt5uMpVyrSCcEf5wVBQKBBb8A6oQQwjXoK8Up+TscjfPdC/O3CUGo3Yt\nS3aOcj42BSj8ysk/CT3dgEAgLjKk38zaV+BViWekV8/duBlYEiDIDnfSuxofyy2A\npn0NAoGBALIlCu5KjZn4pEmWo4AAO66CLseGFNhtcbW6Uy/L0kPdmZMr57rl56iQ\nbezjOSECKsqRTT2xJzJ7NVl4VdnqrQ71+LkYHtIB1znq7WzcCZ4fBnW/rrO8JZ54\nkKwm2gxxEoTlawTqhjp5O6wSu31+hjYPv/xRelMOpGOrqVLqd8nU\n-----END RSA PRIVATE KEY-----\n"
}
