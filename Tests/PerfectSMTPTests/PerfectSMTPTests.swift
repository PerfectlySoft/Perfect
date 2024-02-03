import XCTest
import PerfectLib
import PerfectCURL

@testable import PerfectSMTP

class PerfectSMTPTests: XCTestCase {
	func testSMTP() {
		// note: copy your smtp.test.json into /tmp,
        // for example,
        // {
        //    "url": "smtp://smtp.mailtrap.io",
        //    "username": "aaaabbbccccddd",
        //    "password": "11122223333444",
        //     "requiresTLSUpgrade": true
        // }
        var client: SMTPClient? = nil
        let testCredentialPath = "/tmp/smtp.test.json"
        do {
            let testCredential = try Data(contentsOf: URL(fileURLWithPath: testCredentialPath))
            client = try JSONDecoder().decode(SMTPClient.self, from: testCredential)
        } catch {
            XCTFail("test credential not found, please make up \(testCredentialPath)\nError: \(error)")
        }
        guard let client = client else {
            XCTFail("unable to initialize smtp client")
            return
        }
		let Email = Email(client: client)
		Email.subject = "hello"
		Email.from = Recipient(name: "Judith Smith", address: "judysmith1964@gmx.com")
		Email.content = "<h1>这是一个测试</h1><hr><img src='http://www.perfect.org/images/perfect-logo-2-0.svg'>"
		Email.to.append(Email.from)
		Email.cc.append(Recipient(address: "rockywei@gmx.com"))

		let x = self.expectation(description: "sending mail")
		do {
			let fa = File("/tmp/hello.txt")
			try fa.open(.write)
			try fa.write(string: "Hello, World!")
			fa.close()
			let fb = File("/tmp/hola.txt")
			try fb.open(.write)
			try fb.write(string: "中国🇨🇳Canada🇨🇦")
			fb.close()
			Email.attachments.append("/tmp/hello.txt")
			Email.attachments.append("/tmp/hola.txt")
			Email.debug = true
			let curl = CURL(url: "https://homepages.cae.wisc.edu/~ece533/images/watch.png")
			print("download test example attachements ...")
			let r = curl.performFully()
			print("done.\n")
			if r.0 == 0 {
				let fc = File("/tmp/watch.png")
				try fc.open(.write)
				try fc.write(bytes: r.2)
				fc.close()
				Email.attachments.append("/tmp/watch.png")
			}
			print("sending Email now...")
			try Email.send { code, header, body in
				print(code)
				print(header)
				print(body)
				x.fulfill()
			}
		} catch {
			XCTFail("\(error)")
			x.fulfill()
		}
		self.waitForExpectations(timeout: 60) { err in
			if let timeoutErr = err {
				XCTFail("time out \(timeoutErr.localizedDescription)")
			} else {
				print("Email sent.")
			}
		}
	}
}
