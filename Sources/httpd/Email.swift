//
//  File.swift
//  
//
//  Created by Rockford Wei on 2022-06-25.
//

import Foundation
import PerfectMustache
import PerfectSMTP
import PerfectCRUD

public extension Email {
    private static let queue = DispatchQueue(label: UUID().uuidString)
    static func compose(recepient: String, content: [String: Any], template: String, completion: @escaping (Error?) -> Void) throws {
        let cfg = Settings.default
        let context = MustacheEvaluationContext(templatePath: "\(cfg.pathTemplates)/emails/\(template).mustache", map: content)
        let collector = MustacheEvaluationOutputCollector()
        let email = Email(client: SMTPClient(url: cfg.smtpServerUrl, username: cfg.smtpUsername, password: cfg.smtpPassword, requiresTLSUpgrade: true))
        email.subject = "Invitation"
        email.from = Recipient(name: "admin", address: cfg.email)
        email.content = try context.formulateResponse(withCollector: collector)
        email.to.append(Recipient(address: recepient))
        queue.async {
            do {
                try email.send { code, head, body in
                    CRUDLogging.log(.info, "email to \(recepient) sent: \(code)#\n\(head)\n\(body)")
                    completion(nil)
                }
            } catch {
                completion(error)
            }
        }
    }
}
