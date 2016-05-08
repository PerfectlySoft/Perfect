//
//  MiddlewareResponder.swift
//  PerfectLib
//
//  Created by Sergii Gavryliuk on 2016-05-08.
//  Copyright © 2016 PerfectlySoft. All rights reserved.
//

import Foundation


enum MiddlewareResponse {
    case Terminal(Response)
    case Middleware(MiddlewareResponder -> MiddlewareResponse)
}

protocol MiddlewareResponder {
    func respond(to request: WebRequest) -> MiddlewareResponse
}


final class AnyMiddlewareResponder: MiddlewareResponder {
    let respondHandler: WebRequest -> MiddlewareResponse
    
    init(respondHandler: WebRequest -> MiddlewareResponse) {
        self.respondHandler = respondHandler
    }
    
    func respond(to request: WebRequest) -> MiddlewareResponse {
        return self.respondHandler(request)
    }
}

extension MiddlewareResponder {
    
    func chain(with responder: MiddlewareResponder) -> MiddlewareResponder {
        return AnyMiddlewareResponder { request in
            switch self.respond(to: request) {
            case .Terminal(let response):
                return .Terminal(response)
            case .Middleware(let f):
                return f(responder)
            }
        }
    }
    
    func chain(with responder: Responder) -> Responder {
        return AnyResponder { request in
            switch (self.respond(to: request)) {
            case .Terminal(let response):
                return response
            case .Middleware(let middlewareResponseHandler):
                let middlewareResponder = AnyMiddlewareResponder { request in
                    return .Terminal(responder.respond(to: request))
                }
                switch (middlewareResponseHandler(middlewareResponder)) {
                case .Terminal(let response):
                    return response
                default:
                    // since we feed MiddlewareResponder here that is guaranteed to generate .Terminal response only
                    // this will never happen. Used only to suppress compiler errors
                    fatalError()
                }
            }
        }
    }
}


extension Array where Element: MiddlewareResponder {
    func chain() -> MiddlewareResponder {
        
        let firstResponder = PassThroughResponder(){ _,_ in }
        return self.reduce(firstResponder) {
            return $0.chain(with: $1)
        }
    }
}


final class PassThroughResponder: MiddlewareResponder {
    private let sideEffectFunc: (WebRequest, Response) -> ()
    
    init(sideEffect: (WebRequest, Response) -> ()) {
        self.sideEffectFunc = sideEffect
    }
    
    func respond(to request: WebRequest) -> MiddlewareResponse {
        func middlewareResponder(responder: MiddlewareResponder) -> MiddlewareResponse {
            let response = responder.respond(to: request)
            if case .Terminal(let response) = response {
                self.sideEffectFunc(request, response)
            }
            return response
        }
        return .Middleware(middlewareResponder)
    }
}


// Just an example of the middleware.
// Likely it doesn't belong here. should be moved.

final class LogMiddleware: MiddlewareResponder {
    
    private let passThroughResponder: PassThroughResponder
    init(log: String -> Void ) {
        self.passThroughResponder = PassThroughResponder() {
            request, response in
            log("Request: \(request.path)\nResponse: \(response)")
        }
    }
    
    func respond(to request: WebRequest) -> MiddlewareResponse {
        return self.passThroughResponder.respond(to: request)
    }
}