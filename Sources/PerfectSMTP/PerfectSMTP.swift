//
//  SMTP.swift
//  Perfect-SMTP
//
//  Created by Rockford Wei on 2016-12-28.
//  Copyright © 2016 PerfectlySoft. All rights reserved.
//
// ===----------------------------------------------------------------------===//
//
// This source file is part of the Perfect.org open source project
//
// Copyright (c) 2016 - 2017 PerfectlySoft Inc. and the Perfect project authors
// Licensed under Apache License v2.0
//
// See http://perfect.org/licensing.html for license information
//
// ===----------------------------------------------------------------------===//
//

import Foundation
import PerfectLib
import PerfectCURL
import PerfectCrypto
import PerfectHTTP

/// SMTP Common Errors
public enum SMTPError: Error {
	/// void subject is not allowed
	case INVALID_SUBJECT
	/// void sender is not allowed
	case INVALID_FROM
	/// void recipient is not allowed
	case INVALID_RECIPIENT
	/// bad memory allocation
	case INVALID_BUFFER
	/// void mail body is not allowed
	case INVALID_CONTENT
	/// unacceptable protocol
	case INVALID_PROTOCOL
	/// base64 failed
	case INVALID_ENCRYPTION

	case general(Int, String)
}

/// SMTP login structure
public struct SMTPClient: Codable {
	/// smtp://smtp.mail.server or smtps://smtp.mail.server
	public var url = ""
	/// login name: user@mail.server
	public var username = ""
	/// login secret
	public var password = ""
	/// upgrade connection to use TLS
	public var requiresTLSUpgrade = false
	/// constructor
	/// - parameters:
	///   - url: String, smtp://somewhere or smtps://someelsewhere
	///   - username: String, user@somewhere
	///   - password: String
	public init(url: String = "", username: String = "", password: String = "", requiresTLSUpgrade: Bool = false) {
		self.url = url
		self.username = username
		self.password = password
		self.requiresTLSUpgrade = requiresTLSUpgrade
	}
}

/// Email receiver format, "Full Name" <nickname@some.where>
public struct Recipient: Codable {
	/// Full Name
	public var name = ""
	/// Email address, nickname@some.where
	public var address = ""
	/// constructor
	/// - parameters:
	///   - name: full name of the Email receiver / recipient
	///   - address: Email address, i.e., nickname@some.where
	public init(name: String = "", address: String = "") {
		self.name = name
		self.address = address
	}
}

/// string extension for express conversion from recipient, etc.
extension String {
	func base64Encoded() -> String? {
		if let data = self.data(using: .utf8) {
			return data.base64EncodedString()
		}
		return nil
	}

	/// get RFC 5322-compliant date for Email
	static var rfc5322Date: String {
		let dateFormatter = DateFormatter()
		dateFormatter.locale = Locale.current
		dateFormatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss Z"
		let compliantDate = dateFormatter.string(from: Date())
		return compliantDate
	}

	/// convert a recipient to standard Email format: "Full Name"<nickname@some.where>
	/// - parameters:
	///   - recipient: the Email receiver name / address structure
	init(recipient: Recipient) {
		// full name can be ignored
		if recipient.name.isEmpty {
			self = recipient.address
		} else {
			if let recipientNameB64 = recipient.name.base64Encoded() {
				self = "=?utf-8?B?\(recipientNameB64)?= <\(recipient.address)>"
			} else {
				self = "\"\(recipient.name)\" <\(recipient.address)>"
			}
		}
	}

	/// convert a group of recipients into an address list, joined by comma
	/// - parameters:
	///   - recipients: array of recipient
	init(recipients: [Recipient]) {
		self = recipients.map { String(recipient: $0) }.joined(separator: ", ")
	}

	/// MIME mail header: To/Cc/Bcc + recipients
	/// - parameters:
	///   - prefix: To / Cc or Bcc
	///   - recipients: mailing list
	init(prefix: String, recipients: [Recipient]) {
		let r = String(recipients: recipients)
		self = "\(prefix): \(r)\r\n"
	}

	/// get the address info from a recipient, i.e, someone@somewhere -> @somewhere
	var EmailSuffix: String {
        guard let at = firstIndex(of: "@") else {
			return self
		}
		return String(self[at..<endIndex])
	}

	/// extract file name from a full path
	var fileNameWithoutPath: String {
		let segments = self.split(separator: "/")
		return String(segments[segments.count - 1])
	}

	/// extract file suffix from a file name
	var suffix: String {
		let segments = self.split(separator: ".")
		return String(segments[segments.count - 1])
	}
}

private struct EmailBodyGen: CURLRequestBodyGenerator {
	let bytes: [UInt8]
	var offset = 0
	var contentLength: Int? { return bytes.count }

	init(_ string: String) {
		bytes = Array(string.utf8)
	}

	mutating func next(byteCount: Int) -> [UInt8]? {
		let count = bytes.count
		let remaining = count - offset
		guard remaining > 0 else {
			return nil
		}
		let ret = Array(bytes[offset..<(offset + min(byteCount, remaining))])
		offset += ret.count
		return ret
	}
}

/// SMTP mail composer
public class Email {
	/// boundary for mark different part of the mail
	let boundary = "perfect-smtp-boundary"
	/// login info of a valid mail
	public var client: SMTPClient
	/// mail receivers
	public var to: [Recipient] = []
	/// mail receivers
	public var cc: [Recipient] = []
	/// mail receivers / will not be displayed in to / cc recipients
	public var bcc: [Recipient] = []
	/// mail sender info
	public var from: Recipient = Recipient()
	/// title of the Email
	public var subject: String = ""
	/// attachements of the mail - file name with full path
	public var attachments: [String] = []
	/// Email content body
	public var content: String = ""
	// text version, to be added with a html version.
	public var text: String = ""
	/// an alternative name of content
	public var html: String {
		get { return content }
		set { content = newValue }
	}
	public var reference: String = ""
	public var connectTimeoutSeconds: Int = 15
	/// for debugging purposes
	public var debug = false

	var progress = 0

	/// constructor
	/// - parameters:
	///   - client: SMTP client for login info
	public init(client: SMTPClient) {
		self.client = client
	}

	/// transform an attachment into an MIME part
	/// - parameters:
	///   - path: local full path
	///   - mimeType: i.e., text/plain for txt, etc.
	/// - returns
	/// MIME encoded content with boundary
	@discardableResult
	private func attach(path: String, mimeType: String) -> String {
		// extract file name from full path
		let file = path.fileNameWithoutPath
		guard !file.isEmpty else {
			return ""
		}
		do {
			// get base64 encoded text
			guard let data = try encode(path: path) else {
				return ""
			}
			let disposition = "attachment"
			if self.debug {
				print("\(data.utf8.count) bytes attached")
			}
			// pack it up to an MIME part
			let filename = paramterRfc2231(something: file)
			let name = contentTypefilenameParameter(something: file)
			return
"""
--\(boundary)
Content-Disposition: \(disposition);
filename*=\(filename)
Content-Type: \(mimeType);
name=\"\(name)\"\r\n"
Content-Transfer-Encoding: base64
\r\n\(data)\r\n
"""
		} catch {
			return ""
		}
	}

	/// https://www.ietf.org/rfc/rfc2047.txt
	/// encode a string to url encode conform string
	/// - parameters:
	///   - something: a string to be encoded
	/// - returns:
	/// base64 but rfc2047 conform string
	private func contentTypefilenameParameter(something: String) -> String {
		let something = something.base64Encoded()!
		// from rfc2047 encoded-word = "=?" charset "?" encoding "?" encoded-text "?="
		//   Q is "Quoted-Printable" content-transfer-encoding defined in RFC 2045
		//   B is Base64
		return "=?utf-8?B?\(something)?="
	}

	/// https://tools.ietf.org/html/rfc2231
	/// encode a string to url encode conform string
	/// - parameters:
	///   - something: a string to be encoded
	/// - returns:
	/// url encoded string
	private func paramterRfc2231(something: String) -> String {
		let something = something.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!
		return "utf-8''\(something)"
	}
	/// encode a file by base64 method
	/// - parameters:
	///   - path: full path of the file to encode
	/// - returns:
	/// base64 encoded text WITH A TRAILING NEWLINE
	@discardableResult
	private func encode(path: String) throws -> String? {
		return FileManager.default.contents(atPath: path)?.base64EncodedString(options: .init(arrayLiteral: [.endLineWithCarriageReturn, .endLineWithLineFeed, .lineLength76Characters]))
	}

	private func makeBody() throws -> (String, String) {
		// !FIX! quoted printable?
		var body = "Date: \(String.rfc5322Date)\r\n"
		progress = 0
		// add the "To: " section
		if to.count > 0 {
			body += String(prefix: "To", recipients: to)
		}
		// add the "From: " section
		if from.address.isEmpty {
			throw SMTPError.INVALID_FROM
		} else {
			let f = String(recipient: from)
			body += "From: \(f)\r\n"
		}
		// add the "Cc: " section
		if cc.count > 0 {
			body += String(prefix: "Cc", recipients: cc)
		}
		// add the "Bcc: " section
		if bcc.count > 0 {
			body += String(prefix: "Bcc", recipients: bcc)
		}
		// add the uuid of the Email to avoid duplicated shipment
		let uuid = UUID().uuidString
		body += "Message-ID: <\(uuid).Perfect-SMTP\(from.address.EmailSuffix)>\r\n"
		if reference != "" {
			body += "In-Reply-To: \(reference)\r\n"
			body += "References: \(reference)\r\n"
		}

		// add the Email title
		if subject.isEmpty {
			throw SMTPError.INVALID_SUBJECT
		} else {
			if let subjectB64 = subject.base64Encoded() {
				body += "Subject: =?utf-8?B?\(subjectB64)?=\r\n"
			} else {
				body += "Subject: =?utf-8?Q?\(subject)?=\r\n"
			}
		}
		// mark the content type
		body += "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"\(boundary)\"\r\n\r\n"
		// add the html / plain text content body
		guard  !(content.isEmpty && text.isEmpty) else {
			throw SMTPError.INVALID_CONTENT
		}
		let alternative = !content.isEmpty && !text.isEmpty
		if alternative {
			let boundary2 = boundary + "-2"
			body += "--\(boundary)\r\nContent-Type: multipart/alternative; boundary=\(boundary2)\r\n\r\n"
			body += "--\(boundary2)\r\nContent-Type: text/plain; charset=UTF-8; format=flowed\r\n\r\n\(text)\r\n"
			body += "--\(boundary2)\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n\(content)\r\n"
			body += "--\(boundary2)--\r\n"
		} else {
			if !text.isEmpty {
				body += "--\(boundary)\r\nContent-Type: text/plain; charset=UTF-8; format=flowed\r\n\r\n\(text)\r\n"
			}
			if !content.isEmpty {
				body += "--\(boundary)\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n\(content)\r\n"
			}
		}
		// add the attachements
		body += attachments.map { attach(path: $0, mimeType: MimeType.forExtension($0.suffix)) }.joined(separator: "")
		// end of the attachements
		body += "--\(boundary)--\r\n"
		return (body, uuid)
	}

	private func getResponse(_ body: String) throws -> CURLResponse {
		let recipients = to + cc + bcc
		guard recipients.count > 0 else {
			throw SMTPError.INVALID_RECIPIENT
		}
		var options: [CURLRequest.Option] = (debug ? [.verbose] : []) + [
			.mailFrom(from.address),
			.userPwd("\(client.username):\(client.password)"),
			.upload(EmailBodyGen(body)),
			.connectTimeout(connectTimeoutSeconds)]
		options.append(contentsOf: recipients.map { .mailRcpt($0.address) })
		if client.url.lowercased().hasPrefix("smtps") || client.requiresTLSUpgrade {
			options.append(.useSSL)
		}
		let request = CURLRequest(client.url, options: options)
		return try request.perform()
	}

	/// send an Email with the current settings
	/// - parameters:
	///   - completion: once sent, callback to the main thread with curl code, header & body string
	/// - throws:
	/// SMTPErrors
	public func send(completion: ((Int, String, String) -> ())? = nil) throws {
		let (body, uuid) = try makeBody()
		let response = try getResponse(body)
		let code = response.responseCode
		if let c = completion {
			return c(code, uuid, response.bodyString)
		}
		guard code > 199 && code < 300 else {
			throw SMTPError.general(code, response.bodyString)
		}
	}
}
