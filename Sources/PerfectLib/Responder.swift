//
//  Responder.swift
//  PerfectLib
//
//  Created by Sergii Gavryliuk on 2016-04-25.
//  Copyright © 2016 PerfectlySoft. All rights reserved.
//

import Foundation


protocol Responder {
    func respond(to request: WebRequest) -> Response
}

final class AnyResponder: Responder {
    let repondHandler: WebRequest -> Response
    
    init(_ respondHandler: WebRequest -> Response) {
        self.repondHandler = respondHandler
    }
    
    func respond(to request: WebRequest) -> Response {
        return self.repondHandler(request)
    }
}

final class ResponderChainTerminator: Responder {
    let responderChain: MiddlewareResponder
    
    init(chain: MiddlewareResponder) {
        self.responderChain = chain
    }
    
    func respond(to request: WebRequest) -> Response {
        switch self.responderChain.respond(to: request) {
        case .Terminal(let response):
            return response
        case .Middleware:
            return .InternalError("No handler for request \(request.path!)")
        }
    }
}




