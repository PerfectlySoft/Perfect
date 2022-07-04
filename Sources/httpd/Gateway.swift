import Foundation
import PerfectAuth
import PerfectCRUD
import PerfectLib
import PerfectHTTP
import PerfectHTTPServer
import PerfectMustache
import PerfectSMTP

public struct Gateway {

    public struct LoginResponse: Codable {
        var error = ""
        var token = ""
    }
    // swiftlint:disable comma
    public static func load(routes: Routes = Routes()) throws -> Routes {
        var routes = routes
        routes.add(method: .post,   uri: "/api/invite",         handler: invite)
        routes.add(method: .post,   uri: "/api/register",       handler: resetPassword)
        routes.add(method: .post,   uri: "/api/login",          handler: login)
        routes.add(method: .post,   uri: "/api/reset/attempt",  handler: resetPasswordRequest)
        routes.add(method: .post,   uri: "/api/reset/confirm",  handler: resetPassword)
        routes.add(method: .get,    uri: "/p/account/new",      handler: accountNew)
        routes.add(method: .get,    uri: "/p/account/reset",    handler: accountReset)
        routes.add(method: .get,    uri: "/s/api/secret",       handler: secretResource)
        routes.add(method: .get,    uri: "/**",                 handler: template)
        return routes
    }

    public static let requestFitlers: [(HTTPRequestFilter, HTTPFilterPriority)] = [
        (PostControl(), .high),
        (Security(), .high)
    ]
    public struct PostControl: HTTPRequestFilter {
        public func filter(request: HTTPRequest, response: HTTPResponse, callback: (HTTPRequestFilterResult) -> ()) {
            if request.method == .get {
                callback(.continue(request, response))
                return
            }
            guard let nonce = request.header(.xCsrfToken) else {
                CRUDLogging.log(.warning, "post header must include a nonce token for CSRF")
                callback(.halt(request, response))
                return
            }
            do {
                try Nonce.validate(nonce: nonce, seconds: Settings.default.validTokenSeconds, authorityPublicKey: Settings.default.keyPublic)
                callback(.continue(request, response))
            } catch {
                CRUDLogging.log(.warning, "invalid CSRF token: \(nonce) because \(error)")
                callback(.halt(request, response))
            }
        }
    }
    public struct Security: HTTPRequestFilter {
        public func filter(request: HTTPRequest, response: HTTPResponse, callback: (HTTPRequestFilterResult) -> ()) {
            request.scratchPad.removeValue(forKey: Account.scratchPadKey)
            if request.uri.hasPrefix("/s/") {
                if let jwt = request.header(.authorization)?.replacingOccurrences(of: "Bearer ", with: "") {
                    do {
                        let account = try Account.load(jsonWebToken: jwt)
                        request.scratchPad[Account.scratchPadKey] = account.id
                        callback(.continue(request, response))
                    } catch {
                        callback(.halt(request, response))
                    }
                } else {
                    callback(.halt(request, response))
                }
            } else {
                callback(.continue(request, response))
            }
        }
    }
    public static let staticHandler = StaticFileHandler(documentRoot: Settings.default.pathWebroot).handleRequest(request:response:)
    public static func template(request: HTTPRequest, response: HTTPResponse) {
        if File(cfg.pathWebroot + request.uri).exists && request.uri != "/" {
            staticHandler(request, response)
            return
        }
        let tempPath = cfg.pathTemplates + "/pages"
        let path: String
        if request.uri == "/" {
            path = tempPath + "/index.mustache"
        } else {
            path = tempPath + request.uri.replacingOccurrences(of: ".html", with: ".mustache")
                            .replacingOccurrences(of: ".htm", with: ".mustache")
        }
        if File(path).exists {
            var meta: [String: String] = [:]
            if let nonce = (try? Nonce.allocate(authorityPrivateKey: cfg.keyPrivate)) {
                meta["csrf"] = nonce
            }
            if let jwt = request.header(.authorization) {
                meta["auth"] = jwt
            } else if let id = request.scratchPad[Account.scratchPadKey] as? String,
                      let id = UUID(uuidString: id),
                      let account = try? Account.lookup(id: id),
                      let jwt = try? account.claimJWT() {
                meta["jwt"] = "Bearer \(jwt)"
            } else {
                meta["jwt"] = ""
            }
            let context = MustacheEvaluationContext(templatePath: path, map: meta)
            let collector = MustacheEvaluationOutputCollector()
            do {
                let html = try context.formulateResponse(withCollector: collector)
                response.setHeader(.contentType, value: MimeType.html)
                response.setBody(string: html)
            } catch {
                response.setHeader(.contentType, value: MimeType.json)
                response.setBody(string: error.jsonString)
            }
        } else {
            response.setHeader(.contentType, value: MimeType.text)
            response.setBody(string: "404 File not found")
        }
        response.completed()
    }
    public static func invite(request: HTTPRequest, response: HTTPResponse) {
        struct InvitationRequest: Codable {
            let email: String
        }
        response.setHeader(.contentType, value: MimeType.json)
        do {
            guard let invitationRequest = try request.postBodyJson(InvitationRequest.self) else {
                throw Exception.invalidJSON
            }
            guard nil == (try Account.find(email: invitationRequest.email)) else {
                throw Exception.accountExists
            }
            let account = Account(email: invitationRequest.email, status: AccountState.signedUp.rawValue, admin: 0, shadow: "", salt: "")
            _ = try account.save()
            let code = try Account.requestPasswordReset(email: account.email)
            let cfg = Settings.default
            let content: [String: Any] = [
                "name": cfg.name,
                "url": "\(cfg.url)/p/account/new?code=\(code.uuidString.lowercased())",
                "minutes": cfg.validResetSeconds / 60
            ]
            try Email.compose(recepient: account.email, content: content, template: "invitation") { error in
                let error = error ?? Exception.ok
                response.setBody(string: error.jsonString)
                response.completed()
            }
        } catch {
            response.setBody(string: error.jsonString)
            response.completed()
        }
    }
    public static func accountNew(request: HTTPRequest, response: HTTPResponse) {
        guard let param = (request.queryParams.first { $0.0 == "code"}),
            let code = UUID(uuidString: param.1) else {
            response.setHeader(.contentType, value: MimeType.text)
            response.status = .badRequest
            response.setBody(string: "400 Bad Request")
            response.completed()
            return
        }
        let cfg = Settings.default
        do {
            let id = try Access.recover(code: code)
            guard let account = try Account.lookup(id: id) else {
                throw Exception.invalidAccount
            }
            var content: [String: Any] = [
                "name": cfg.name,
                "email": account.email,
                "code": code.uuidString.lowercased(),
                "minutes": cfg.validResetSeconds / 60
            ]
            if let nonce = (try? Nonce.allocate(authorityPrivateKey: cfg.keyPrivate)) {
                content["csrf"] = nonce
            }
            let context = MustacheEvaluationContext(templatePath: "\(cfg.pathTemplates)/pages/accountnew.mustache", map: content)
            let collector = MustacheEvaluationOutputCollector()
            let html = try context.formulateResponse(withCollector: collector)
            response.setHeader(.contentType, value: MimeType.html)
            response.setBody(string: html)
        } catch {
            response.setHeader(.contentType, value: MimeType.text)
            response.status = .badRequest
            response.setBody(string: "\(error)")
        }
        response.completed()
    }
    public static func resetPassword(request: HTTPRequest, response: HTTPResponse) {
        struct Form: Codable {
            let code: String
            let password: String
        }
        do {
            guard let form = try request.postBodyJson(Form.self),
            let code = UUID(uuidString: form.code) else {
                throw Exception.invalidJSON
            }
            let account = try Account.resetPassword(code: code, password: form.password)
            let jwt = try account.claimJWT()
            let resp = LoginResponse(error: "ok", token: jwt)
            try response.setBody(json: resp)
        } catch {
            response.setHeader(.contentType, value: MimeType.json)
            response.setBody(string: error.jsonString)
        }
        response.completed()
    }
    public static func login(request: HTTPRequest, response: HTTPResponse) {
        struct Form: Codable {
            let email: String
            let password: String
        }
        struct Resp: Codable {
            let token: String
        }
        do {
            guard let form = try request.postBodyJson(Form.self) else {
                throw HTTPResponseError(status: .badRequest, description: "access denied")
            }
            let account = try Account.signIn(email: form.email, password: form.password)
            let jwt = try account.claimJWT()
            let resp = Resp(token: jwt)
            try response.setBody(json: resp)
        } catch {
            response.setHeader(.contentType, value: MimeType.json)
            response.setBody(string: error.jsonString)
        }
        response.completed()
    }
    public static func validate(request: HTTPRequest, response: HTTPResponse) {
        response.setHeader(.contentType, value: "application/json")
        response.appendBody(string: Settings.default.json)
        response.completed()
    }
    public static func resetPasswordRequest(request: HTTPRequest, response: HTTPResponse) {
        struct InvitationRequest: Codable {
            let email: String
        }
        response.setHeader(.contentType, value: MimeType.json)
        do {
            guard let invitationRequest = try request.postBodyJson(InvitationRequest.self) else {
                throw Exception.invalidJSON
            }
            guard let account = try Account.find(email: invitationRequest.email) else {
                throw Exception.invalidAccount
            }
            let code = try Account.requestPasswordReset(email: account.email)
            let cfg = Settings.default
            let content: [String: Any] = [
                "name": cfg.name,
                "url": "\(cfg.url)/p/account/reset?code=\(code.uuidString.lowercased())",
                "minutes": cfg.validResetSeconds / 60
            ]
            try Email.compose(recepient: account.email, content: content, template: "passwordreset") { error in
                let error = error ?? Exception.ok
                response.setBody(string: error.jsonString)
                response.completed()
            }
        } catch {
            response.setBody(string: error.jsonString)
            response.completed()
        }
    }
    public static func accountReset(request: HTTPRequest, response: HTTPResponse) {
        guard let param = (request.queryParams.first { $0.0 == "code"}),
            let code = UUID(uuidString: param.1) else {
            response.setHeader(.contentType, value: MimeType.text)
            response.status = .badRequest
            response.setBody(string: "400 Bad Request")
            response.completed()
            return
        }
        let cfg = Settings.default
        do {
            let id = try Access.recover(code: code)
            guard let account = try Account.lookup(id: id) else {
                throw Exception.invalidAccount
            }
            var content: [String: Any] = [
                "name": cfg.name,
                "email": account.email,
                "code": code.uuidString.lowercased(),
                "minutes": cfg.validResetSeconds / 60
            ]
            if let nonce = (try? Nonce.allocate(authorityPrivateKey: cfg.keyPrivate)) {
                content["csrf"] = nonce
            }
            let context = MustacheEvaluationContext(templatePath: "\(cfg.pathTemplates)/pages/accountreset.mustache", map: content)
            let collector = MustacheEvaluationOutputCollector()
            let html = try context.formulateResponse(withCollector: collector)
            response.setHeader(.contentType, value: MimeType.html)
            response.setBody(string: html)
        } catch {
            response.setHeader(.contentType, value: MimeType.text)
            response.status = .badRequest
            response.setBody(string: "\(error)")
        }
        response.completed()
    }
    public static func secretResource(request: HTTPRequest, response: HTTPResponse) {
        struct Secret: Codable {
            let content: String
        }
        let secret = Secret(content: "you found me!")
        _ = try? response.setBody(json: secret)
        response.completed()
    }
}
