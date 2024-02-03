import XCTest
@testable import PerfectCrypto
import Foundation
import PerfectLib

extension File {
	/// write a random binary file
	/// - parameter totalBytes: the expected size to generate
	/// - parameter bufferSize: the buffer size to apply in file writing
	/// - throws: CryptoError in case of exceptions.
	public func random(totalBytes: Int, bufferSize: Int = 16384) throws {
		let szbuf = bufferSize > 0 ? bufferSize : 16384
		guard totalBytes > 0 else {
			throw CryptoError(code: -1, msg: "invalid parameter")
		}
		self.delete()
		try self.open(.write)
		var size = 0
		var remain = totalBytes
		repeat {
			size = min(remain, szbuf)
			remain -= size
            // swiftlint:disable syntactic_sugar
			let buf = Array<UInt8>(randomCount: size)
			try self.write(bytes: buf)
		} while remain > 0
		self.close()
		guard self.size == totalBytes else {
			throw CryptoError(code: -2, msg: "unexpected size \(totalBytes) != \(self.size)")
		}
	}
}

class PerfectCryptoTests: XCTestCase {

	override func setUp() {
		_ = PerfectCrypto.isInitialized
	}

	func testInitialized() {
		XCTAssert(PerfectCrypto.isInitialized)
	}

	func testHexEncDec1() {
		let testStr = "Hello, world!"
		guard let hexBytes = testStr.encode(.hex) else {
			return XCTAssert(false)
		}
		XCTAssert(String(validatingUTF8: hexBytes) == "48656c6c6f2c20776f726c6421")
		guard let unHex = hexBytes.decode(.hex) else {
			return XCTAssert(false)
		}
		XCTAssert(String(validatingUTF8: unHex) == testStr)
	}

	func test64EncDec1() {
		let testStr = "Hello, world!"
		guard let baseBytes = Array(testStr.utf8).encode(.base64) else {
			return XCTAssert(false)
		}
		XCTAssert(String(validatingUTF8: baseBytes) == "SGVsbG8sIHdvcmxkIQ==")
		guard let unHex = baseBytes.decode(.base64) else {
			return XCTAssert(false)
		}
		XCTAssert(String(validatingUTF8: unHex) == testStr)
	}

	func test64EncDec2() {
		let testStr = "Räksmörgåsen"
		guard let baseBytes = Array(testStr.utf8).encode(.base64) else {
			return XCTAssert(false)
		}
		guard let s = String(validatingUTF8: baseBytes) else {
			return XCTAssert(false)
		}
		XCTAssert(s == "UsOka3Ntw7ZyZ8Olc2Vu")
		guard let unHex = s.decode(.base64) else {
			return XCTAssert(false)
		}
		XCTAssert(String(validatingUTF8: unHex) == testStr)
	}

	func test64EncDec3() {
		let testStr = "🤡 Räksmörgåsen"
		guard let baseBytes = Array(testStr.utf8).encode(.base64url) else {
			return XCTAssert(false)
		}
		let baseStr = String(validatingUTF8: baseBytes)
		XCTAssert(baseStr == "8J-koSBSw6Rrc23DtnJnw6VzZW4", "\(String(describing: baseStr))")
		guard let unHex = baseBytes.decode(.base64url) else {
			return XCTAssert(false)
		}
		let unhexed = String(validatingUTF8: unHex)
		XCTAssert(unhexed == testStr, "\(String(describing: unhexed))")
	}

	func testHexEncDec2() {
		let testStr = "Hello, world!"
		guard let hexBytes = Array(testStr.utf8).encode(.hex) else {
			return XCTAssert(false)
		}
		guard let s = String(validatingUTF8: hexBytes) else {
			return XCTAssert(false)
		}
		XCTAssert(s == "48656c6c6f2c20776f726c6421")
		guard let unHex = s.decode(.hex) else {
			return XCTAssert(false)
		}
		XCTAssert(String(validatingUTF8: unHex) == testStr)
	}

	func testIOPair() {
		let testStr = "Hello, world!"
		let chars = [UInt8](testStr.utf8)
		let count = chars.count
		let pair = IOPair()
		let write = pair.first
		let read = pair.second
		do {
			try write.pair(with: read)
			_ = try chars.withUnsafeBytes { try write.write(bytes: $0) }
			try write.flush()
			let dest = UnsafeMutableRawBufferPointer.allocate(byteCount: 1024, alignment: 0)
			defer {
				dest.deallocate()
			}
			let result = try read.read(dest)
			XCTAssert(result == count)
		} catch {
			XCTAssert(false, "\(error)")
		}
	}

	func testBase64Filter1() {
		let testStr = "Hello, world!"
		let chars = [UInt8](testStr.utf8)
		let count = chars.count
		let chain = Base64Filter().chain(MemoryIO())
		do {
			try chars.withUnsafeBytes {
				XCTAssert(try chain.write(bytes: $0) == count)
			}
			let dest = UnsafeMutableRawBufferPointer.allocate(byteCount: 1024, alignment: 0)
			defer {
				dest.deallocate()
			}
			let result = try chain.flush().read(dest)

			XCTAssert(String(validatingUTF8: UnsafeRawBufferPointer(start: dest.baseAddress, count: result)) == testStr)
		} catch {
			XCTAssert(false, "\(error)")
		}
	}

	func testBase64Filter2() {
		let testStr = "Hello, world!"
		let testAnswer = "SGVsbG8sIHdvcmxkIQ=="
		let chars = [UInt8](testStr.utf8)
		let count = chars.count
		let chain = Base64Filter().chain(MemoryIO())
		do {
			XCTAssert("\(chain)" == "base64 encoding<->(memory buffer)")
			let wrote = try chars.withUnsafeBytes {
				try chain.write(bytes: $0)
			}
			XCTAssert(wrote == count)
			let result = try chain.flush().memory
			XCTAssert(result?.count == testAnswer.utf8.count)
			let resultString = String(validatingUTF8: result)
			XCTAssert(testAnswer == resultString)
		} catch {
			XCTAssert(false, "\(error)")
		}
	}

	func testDigest1() {
		let testStr = "Hello, world!"
		let testAnswer = "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3"

		let dest = UnsafeMutableRawBufferPointer.allocate(byteCount: 1024, alignment: 0)
		defer {
			dest.deallocate()
		}

		do {
			let digest = DigestFilter(.sha256)
			_ = try testStr.utf8.map { $0 }.withUnsafeBytes {
				try digest.chain(NullIO()).write(bytes: $0)
			}

			let resultLen = try digest.get(dest)
			let digestBytes = UnsafeRawBufferPointer(start: dest.baseAddress, count: resultLen)
			guard let hexString = digestBytes.encode(.hex) else {
				return XCTAssert(false)
			}
			defer {
				hexString.deallocate()
			}
			XCTAssert(testAnswer == String(validatingUTF8: UnsafeRawBufferPointer(hexString)), "\(hexString)")
		} catch {
			XCTAssert(false, "\(error)")
		}
	}

	func testDigest2() {
		let testStr = "Hello, world!"
		let testAnswer = "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3"
		guard let enc = testStr.digest(.sha256)?.encode(.hex) else {
			return XCTAssert(false)
		}
		XCTAssert(String(validatingUTF8: enc) == testAnswer)
	}

	func testCipherSizes() {
		let algo = Cipher.des_ede3_cbc
		let bs = algo.blockSize
		let kl = algo.keyLength
		let il = algo.ivLength

		XCTAssertEqual(bs, 8)
		XCTAssertEqual(kl, 24)
		XCTAssertEqual(il, 8)
	}

	func testRandomBuffer1() {
		guard let buff = UnsafeMutableRawBufferPointer.allocateRandom(count: 2048) else {
			return XCTAssert(false)
		}
		defer {
			buff.deallocate()
		}
		XCTAssert(buff.count == 2048)
		guard let enc = UnsafeRawBufferPointer(buff).encode(.hex) else {
			return XCTAssert(false)
		}
		enc.deallocate()
	}

	func testRandomBuffer2() {
		let buff = [UInt8](randomCount: 2048)
		let buff2 = [UInt8](randomCount: 2048)

		XCTAssert(buff != buff2)
	}

	func testCipher1() {
		let cipher = Cipher.aes_256_cbc
		guard let random = UnsafeRawBufferPointer.allocateRandom(count: 2048),
			let key = UnsafeRawBufferPointer.allocateRandom(count: cipher.keyLength),
			let iv = UnsafeRawBufferPointer.allocateRandom(count: cipher.ivLength) else {
				return XCTAssert(false)
		}
		defer {
			random.deallocate()
			key.deallocate()
			iv.deallocate()
		}

		guard let encrypted = random.encrypt(cipher, key: key, iv: iv) else {
			return XCTAssert(false)
		}
		defer {
			encrypted.deallocate()
		}

		let encryptedRaw = UnsafeRawBufferPointer(encrypted)
		guard let decrypted = encryptedRaw.decrypt(cipher, key: key, iv: iv) else {
			return XCTAssert(false)
		}
		defer {
			decrypted.deallocate()
		}

		XCTAssert(decrypted.count == random.count)
		for (a, b) in zip(decrypted, random) {
			XCTAssert(a == b)
		}
	}

	func testCipher2() {
		let cipher = Cipher.aes_256_cbc
		let random = [UInt8](randomCount: 2048)
		let key = [UInt8](randomCount: cipher.keyLength)
		let iv = [UInt8](randomCount: cipher.ivLength)
		guard let encrypted = random.encrypt(cipher, key: key, iv: iv) else {
			return XCTAssert(false)
		}
		guard let decrypted = encrypted.decrypt(cipher, key: key, iv: iv) else {
			return XCTAssert(false)
		}
		XCTAssert(decrypted.count == random.count)
		for (a, b) in zip(decrypted, random) {
			XCTAssert(a == b)
		}
	}

	func testJWTVerify() {
		let tstJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
		let secret = "secret"
		let name = "John Doe"
		guard let jwt = JWTVerifier(tstJwt) else {
			return XCTAssert(false)
		}
		do {
			try jwt.verify(algo: .hs256, key: secret)

			let fndName = jwt.payload["name"] as? String
			XCTAssert(name == fndName!)
		} catch {
			XCTAssert(false, "\(error)")
		}
	}

	func testJWTCreate1() {
		struct JWTObj: Codable {
			let sub: String
			let name: String
			let admin: Bool
		}
		let tstPayload = JWTObj(sub: "1234567890", name: "John Doe", admin: true)
		let secret = "secret"
		let name = "John Doe"
		for _ in 0..<30 {
			do {
				let jwt1 = try JWTCreator(payload: tstPayload)
				let token = try jwt1.sign(alg: .hs256, key: secret)
				guard let jwt = JWTVerifier(token) else {
					return XCTAssert(false)
				}
				let obj = try jwt.verify(algo: .hs256, key: HMACKey(secret), as: JWTObj.self)
				let fndName = obj.name
				XCTAssertEqual(name, fndName)
			} catch {
				XCTFail("\(error)")
			}
		}
	}

	func testJWTCreate2() {
		let tstPayload = ["sub": "1234567890", "name": "John Doe", "admin": true] as [String: Any]
		let name = "John Doe"
        // swiftlint:disable line_length
        let pubKey = "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQAB\n-----END PUBLIC KEY-----\n"
        // swiftlint:disable line_length
		let privKey = "-----BEGIN RSA PRIVATE KEY-----\nMIICWwIBAAKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQABAoGAD+onAtVye4ic7VR7V50DF9bOnwRwNXrARcDhq9LWNRrRGElESYYTQ6EbatXS3MCyjjX2eMhu/aF5YhXBwkppwxg+EOmXeh+MzL7Zh284OuPbkglAaGhV9bb6/5CpuGb1esyPbYW+Ty2PC0GSZfIXkXs76jXAu9TOBvD0ybc2YlkCQQDywg2R/7t3Q2OE2+yo382CLJdrlSLVROWKwb4tb2PjhY4XAwV8d1vy0RenxTB+K5Mu57uVSTHtrMK0GAtFr833AkEA6avx20OHo61Yela/4k5kQDtjEf1N0LfI+BcWZtxsS3jDM3i1Hp0KSu5rsCPb8acJo5RO26gGVrfAsDcIXKC+bQJAZZ2XIpsitLyPpuiMOvBbzPavd4gY6Z8KWrfYzJoI/Q9FuBo6rKwl4BFoToD7WIUS+hpkagwWiz+6zLoX1dbOZwJACmH5fSSjAkLRi54PKJ8TFUeOP15h9sQzydI8zJU+upvDEKZsZc/UhT/SySDOxQ4G/523Y0sz/OZtSWcol/UMgQJALesy++GdvoIDLfJX5GBQpuFgFenRiRDabxrE9MNUZ2aPFaFp+DyAe+b4nDwuJaW2LURbr8AEZga7oQj0uYxcYw==\n-----END RSA PRIVATE KEY-----\n"
		for _ in 0..<30 {
			guard let jwt1 = JWTCreator(payload: tstPayload) else {
				return XCTAssert(false)
			}
			do {
				let key = try PEMKey(source: privKey)
				let token = try jwt1.sign(alg: .rs256, key: key)
				guard let jwt = JWTVerifier(token) else {
					return XCTAssert(false)
				}
				let key2 = try PEMKey(source: pubKey)
				try jwt.verify(algo: .rs256, key: key2)
				let fndName = jwt.payload["name"] as? String
				XCTAssert(name == fndName!)
			} catch {
				XCTAssert(false, "\(error)")
			}
		}
	}

	func testJWTCreate3() {
		let tstPayload = ["sub": "1234567890", "name": "John Doe", "admin": true] as [String: Any]
		let name = "John Doe"
		let pubKey = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENyTiyHJTNSQU3UqvzGxKe9ztD08SeBKWRfdvFi5Dp3hGXTgQE3Hb6v0jHZV62R0T1Uu4b+R3IZV6DeozO7JpSQ==\n-----END PUBLIC KEY-----"
		let privKey = "-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgW3Yv7y/niwo3xaG/Hzq8s+Jnil0jnsMCguCeKKTxG3OgCgYIKoZIzj0DAQehRANCAAQ3JOLIclM1JBTdSq/MbEp73O0PTxJ4EpZF928WLkOneEZdOBATcdvq/SMdlXrZHRPVS7hv5HchlXoN6jM7smlJ\n-----END PRIVATE KEY-----"
		for _ in 0..<30 {
			guard let jwt1 = JWTCreator(payload: tstPayload) else {
				return XCTAssert(false)
			}
			do {
				let key = try PEMKey(source: privKey)
				let token = try jwt1.sign(alg: .es256, key: key)
				guard let jwt = JWTVerifier(token) else {
					return XCTAssert(false)
				}
				let key2 = try PEMKey(source: pubKey)
				try jwt.verify(algo: .es256, key: key2)
				let fndName = jwt.payload["name"] as? String
				XCTAssert(name == fndName!)
			} catch {
				XCTAssert(false, "\(error)")
			}
		}
	}

	func testJWTCreateCert() {
		let tstPayload = ["sub": "1234567890", "name": "John Doe", "admin": true] as [String: Any]
		let name = "John Doe"
		let pubKey = "-----BEGIN CERTIFICATE-----\nMIIDNDCCAhwCCQDH2QBnQs6n6DANBgkqhkiG9w0BAQUFADBcMQswCQYDVQQGEwJB\nVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0\ncyBQdHkgTHRkMRUwEwYDVQQDEwxiYWR0aGluZy5vcmcwHhcNMTcwOTIyMTY0MDI0\nWhcNMTcxMDIyMTY0MDI0WjBcMQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1T\ndGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMRUwEwYDVQQD\nEwxiYWR0aGluZy5vcmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCk\n9+U38uJNgz80opuSLPB9RAMMYzLA10E7Ix0Ge2FI5VVRWR5GItDH3h7fxH8kLyZ+\nX1Qovq4NSXLUIQv6kR+OXhyDa1Q8MYwr9s8UNN24QFBoPGvj06aKfu+u3Kt1ezFD\nea2/DRB5WMFZmKO37LNYUJQZs7/NFFltpt7m0Q3tewYdnzMfChRgzcfKT3I21KMU\nrPACysMInijoWNA93e1cIGpIUT9oNNrTHKQ18VWJjf2DGTlRDw+Lc1AoMtUCjyGQ\nFZ3zyzkt1DvUuu+g+lhTol2ffBx/vMlC9K9Nh+y1O7zddHQhcpM/alcL5o+R5Jnp\nXd3AfO+OYQF2ZN3gBZhdAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAHixAUQ22cpv\n9MKNyaTeiReNeipL1UKDCE/PDIg15WdNjzjcEbZAYqEdga4VnLcxDeV/OsvJDz/r\nioQiZgNTog0f15Q9USi5g1KtZrwParTitfRS/Uh9gjj+cbDj/M/WcIEiCHwMl2Mv\neOMYtyL/asdUQiVJBMvUggU4PDRtVjA+uVKvvv9brcJb+yBy9kSazem4olPGJCz4\nPxqAOUQ6KhQyuhKfLc7qIAej8NGXw5K7fG1e2Gx9etNM8lUZRM2Klo/0rZ5iqiq7\nuI5korDYLIAOXOPRvfP3B3mIakZtg++SnDCgVpU2LdEx9V5eov4qij8VAORS8g9o\nuaXv2Q++efc=\n-----END CERTIFICATE-----\n"
		let privKey = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEApPflN/LiTYM/NKKbkizwfUQDDGMywNdBOyMdBnthSOVVUVke\nRiLQx94e38R/JC8mfl9UKL6uDUly1CEL+pEfjl4cg2tUPDGMK/bPFDTduEBQaDxr\n49Omin7vrtyrdXsxQ3mtvw0QeVjBWZijt+yzWFCUGbO/zRRZbabe5tEN7XsGHZ8z\nHwoUYM3Hyk9yNtSjFKzwAsrDCJ4o6FjQPd3tXCBqSFE/aDTa0xykNfFViY39gxk5\nUQ8Pi3NQKDLVAo8hkBWd88s5LdQ71LrvoPpYU6Jdn3wcf7zJQvSvTYfstTu83XR0\nIXKTP2pXC+aPkeSZ6V3dwHzvjmEBdmTd4AWYXQIDAQABAoIBAEM9Jxhezw546FIz\n1OUHnB3ykquB4zXmhpfr//CcaVKk5tl5UXWUyzQrvLnIBWpiLXZktJDG53pS7ZK4\nxYEjlZEZmtWV8Yd3SoLA3jaGNbjbveo+dlst8TuR8W98UgZYaAPwnHi6gnRzUJuM\nM27L822TqkmvkgWsvaaL1V6O5vZb/sdB1+2vV0uE6kKX0gXoCmkwSc/an7a5tY/O\njLl/AZ/P0yJOnCaEZvkpvauP4lK7tNjl078pn3D3scBumL3/mpAtCDB7uPuC8LZn\nWh6pxgNSE9cCpP96EBQbUskgNqG9k5TCtVO8kaCmuV4aPDLWVELuLuryCDsjAWmD\n/PqMV6ECgYEA1SuPcoLoH/DOA+QL2sXmMzeOY2tKZ39UXoqoGM0Y7WaxIvmF/Uv2\nY7BrEpjwsSATFEDzx7Hfds1iBLdO6yb/3z/ajHpEdXu74Efx5HhHSxwi3JaxqLqx\n1nzHfR6qMeSNuGQpVdQpQKnwVDUipgNIcEDkseIj2MVfiXNtBf7D6psCgYEAxh0R\nN4dwVxV9EJLnd5F/CGyyHAoUfMxIrRBKjJTr/qqq+dnbJMX8PzCkAmuS8r5Lr8nn\nER+iAExf7oQhi27qVlOICoWGrHjcqwsi5Tn9TLokbbQCOrUHHn5N8dCIoPVw3Fpp\ndaS/ko2ThdI1DgDS1jq8UPdBrJ/02fO8XK+P3GcCgYA2Vs5QQHJvgfDiKQWklQHj\nWGwhh74Ft/2HxAyplc6e5aiN49F2CiEatGP276mbXTO/2/bIlt0B6cTsstWZN+3N\nuPc7DAfbctkniO9ucAKscNWqKXfMLRscM96eVGzKHxrJQC8RQ+3oH+m1bX4Rl5Cl\nnMUvWxgML/P0k8nc116VtQKBgClPsmFj6rceEgA8weua+WRmVhWmvHLxnk4IUaNT\nAosOR6zmEt5uMpVyrSCcEf5wVBQKBBb8A6oQQwjXoK8Up+TscjfPdC/O3CUGo3Yt\nS3aOcj42BSj8ysk/CT3dgEAgLjKk38zaV+BViWekV8/duBlYEiDIDnfSuxofyy2A\npn0NAoGBALIlCu5KjZn4pEmWo4AAO66CLseGFNhtcbW6Uy/L0kPdmZMr57rl56iQ\nbezjOSECKsqRTT2xJzJ7NVl4VdnqrQ71+LkYHtIB1znq7WzcCZ4fBnW/rrO8JZ54\nkKwm2gxxEoTlawTqhjp5O6wSu31+hjYPv/xRelMOpGOrqVLqd8nU\n-----END RSA PRIVATE KEY-----\n"
		for _ in 0..<30 {
			guard let jwt1 = JWTCreator(payload: tstPayload) else {
				return XCTAssert(false)
			}
			do {
				let key = try PEMKey(source: privKey)
				let token = try jwt1.sign(alg: .es256, key: key)
				guard let jwt = JWTVerifier(token) else {
					return XCTAssert(false)
				}
				let key2 = try PEMKey(source: pubKey)
				try jwt.verify(algo: .es256, key: key2)
				let fndName = jwt.payload["name"] as? String
				XCTAssert(name == fndName!)
			} catch {
				XCTAssert(false, "\(error)")
			}
		}
	}

	func testCipherCMS1() {
		let cipher = Cipher.aes_256_cbc
		let password = Array("this is a good pw".utf8)
		let salt = Array("this is a salty salt".utf8)
		let randomArray = [UInt8](randomCount: 1029)
		guard let result = randomArray.encrypt(cipher, password: password, salt: salt) else {
			return XCTAssert(false, "\(CryptoError())")
		}
		guard let decryptedAry = result.decrypt(cipher, password: password, salt: salt) else {
			return XCTAssert(false, "\(CryptoError())")
		}
		XCTAssertEqual(decryptedAry, randomArray)
	}

	func testCipherCMS2() {
		let cipher = Cipher.aes_256_cbc
		let password = Array("this is a good pw".utf8)
		let passwordBad = Array("this is a bad pw".utf8)
		let salt = Array("this is a salty salt".utf8)
		let randomArray = [UInt8](randomCount: 1029)
		guard let result = randomArray.encrypt(cipher, password: password, salt: salt) else {
			return XCTAssert(false, "\(CryptoError())")
		}
		let decryptedAry = result.decrypt(cipher, password: passwordBad, salt: salt)
		XCTAssertNil(decryptedAry)
	}

	func testCipherCMS3() {
		let cipher = Cipher.aes_256_cbc
		let password = "this is a good pw"
		let salt = "this is a salty salt"
		let data = (1...1000).map { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz\($0)" }.joined(separator: "\n")
		guard let result = data.encrypt(cipher, password: password, salt: salt) else {
			return XCTAssert(false, "\(CryptoError())")
		}
		guard let decryptedData = result.decrypt(cipher, password: password, salt: salt) else {
			return XCTAssert(false, "\(CryptoError())")
		}
		XCTAssertEqual(decryptedData, data)
	}

	func testHMACKey() {
		let password = "this is a good pw"
		let data = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

		if let signed = data.sign(.sha1, key: HMACKey(password))?.encode(.base64),
			let base64Str = String(validatingUTF8: signed),

			let reRawData = base64Str.decode(.base64) {

			let verifyResult = data.verify(.sha1, signature: reRawData, key: HMACKey(password))
			XCTAssert(verifyResult)
		} else {
			XCTAssert(false, "Failed signing")
		}
	}

	func testKeyGen() {
		do {
			let bits = 1024
			struct JSONPayload: Codable {
				let id: Foundation.UUID
				let expires: Int
			}
			let payload = JSONPayload(id: UUID(), expires: time(nil) + 3600)
			let jwt = try JWTCreator(payload: payload)
			do {
				let keyPair = try PEMKey(type: .rsa, bits: bits)
				guard let pubKey = keyPair.publicKey,
					let privKey = keyPair.privateKey else {
						return XCTFail("Unable to get pub/priv keys")
				}
				XCTAssert(keyPair.publicKeyString!.hasPrefix("-----BEGIN RSA PUBLIC KEY-----"))
				XCTAssert(keyPair.privateKeyString!.hasPrefix("-----BEGIN RSA PRIVATE KEY-----"))
				let signed = try jwt.sign(alg: .rs256, key: privKey)
				guard let jwtVer = JWTVerifier(signed) else {
					return XCTFail("JWT verify failed")
				}
				let obj = try jwtVer.verify(algo: .rs256, key: pubKey, as: JSONPayload.self)
				XCTAssertEqual(obj.id, payload.id)
			}
			do {
				let keyPair = try PEMKey(type: .dsa, bits: bits)
				let pubKey = keyPair.publicKey
				let privKey = keyPair.privateKey
				XCTAssertNotNil(pubKey)
				XCTAssertNotNil(privKey)
				XCTAssert(keyPair.publicKeyString!.hasPrefix("-----BEGIN PUBLIC KEY-----"))
				XCTAssert(keyPair.privateKeyString!.hasPrefix("-----BEGIN DSA PRIVATE KEY-----"))
			}
			do {
				let keyPair = try PEMKey(type: .ec, bits: bits)
				guard let pubKey = keyPair.publicKey,
					let privKey = keyPair.privateKey else {
						return XCTFail("Unable to get pub/priv keys")
				}
				XCTAssert(keyPair.publicKeyString!.hasPrefix("-----BEGIN PUBLIC KEY-----"))
				XCTAssert(keyPair.privateKeyString!.hasPrefix("-----BEGIN EC PRIVATE KEY-----"))
				let signed = try jwt.sign(alg: .es256, key: privKey)
				guard let jwtVer = JWTVerifier(signed) else {
					return XCTFail("JWT verify failed")
				}
				let obj = try jwtVer.verify(algo: .es256, key: pubKey, as: JSONPayload.self)
				XCTAssertEqual(obj.id, payload.id)
			}
		} catch {
			XCTFail("\(error)")
		}
	}

	func runProc(cmd: String, args: [String]) throws -> String? {
		#if os(Linux)
			let command: [String] = [cmd] + args
			let fd = popen(command.joined(separator: " "), "r")
			var rd = 0
			let _bufferSize = 16384
			let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: _bufferSize)
			defer {
				buffer.deallocate()
			}
			var buf: [UInt8] = []
			repeat {
				buffer.initialize(to: 0)
				rd = fread(buffer, 1, _bufferSize, fd)
				if rd > 0 {
					let array = UnsafeBufferPointer<UInt8>(start: buffer, count: rd)
					buf.append(contentsOf: Array(array))
				}
			} while rd > 0
			pclose(fd)
		#else
			let task = Process()
			task.launchPath = cmd
			task.arguments = args
			task.environment = ["PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"]
			let oup = Pipe()
			task.standardOutput = oup
			task.launch()
			task.waitUntilExit()
			let buf = oup.fileHandleForReading.readDataToEndOfFile()
		#endif
		return String(bytes: buf, encoding: .utf8)
	}

	func openssl(command: String, file: String) throws -> String {
		guard let output = try runProc(cmd: "/usr/bin/openssl", args: [command, file]),
			let eq = output.firstIndex(of: "=") else {
				throw CryptoError(code: -11, msg: "openssl failed")
		}
		let chopped = output[eq..<output.endIndex].dropFirst(2).dropLast()
		return String(chopped)
	}

	func validate(file: String, digest: [UInt8], by: String) throws {
		guard let hex = digest.encode(.hex),
			let fingerprint = String(validatingUTF8: hex)
			else {
				throw CryptoError(code: -22, msg: "heximal encoding failure")
		}
		let answer = try openssl(command: by, file: file)
		XCTAssertEqual(answer, fingerprint)
	}

	func testFileDigestBy(size: Int, alg: Digest, name: String) throws {
		let file = File("/tmp/\(name)-\(size).txt")
		file.delete()
		try file.random(totalBytes: size)
		let dg = try file.digest(alg)
		try validate(file: file.path, digest: dg, by: name)
	}

	func testFileDigest(alg: Digest, name: String) throws {
		try testFileDigestBy(size: 31, alg: alg, name: name)
		try testFileDigestBy(size: 15838, alg: alg, name: name)
		try testFileDigestBy(size: 1048573, alg: alg, name: name)
	}
/*
	func testFiles() {
		do {
			try testFileDigest(alg: .md4, name: "md4")
			try testFileDigest(alg: .md5, name: "md5")
//			try testFileDigest(alg: .sha, name: "sha")
			try testFileDigest(alg: .sha1, name: "sha1")
//			#if os(OSX)
				try testFileDigest(alg: .sha224, name: "sha224")
				try testFileDigest(alg: .sha256, name: "sha256")
				try testFileDigest(alg: .sha384, name: "sha384")
				try testFileDigest(alg: .sha512, name: "sha512")
				try testFileDigest(alg: .whirlpool, name: "whirlpool")
//			#else
				try testFileDigest(alg: .ripemd160, name: "rmd160")
//			#endif
		} catch {
			XCTFail(error.localizedDescription)
		}
	}
*/
}
