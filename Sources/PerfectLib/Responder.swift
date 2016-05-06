//
//  Responder.swift
//  PerfectLib
//
//  Created by Sergii Gavryliuk on 2016-04-25.
//  Copyright © 2016 PerfectlySoft. All rights reserved.
//

import Foundation

public struct Response {
    var statusCode: (Int, String) = (0, "")
    var body: DataObservableType
    var headers: [String: String] = [:]
    var cookies: [Cookie] = []
    var keepAlive: Bool = false
    
    init(statusCode: (Int, String) = (200, "OK"), body: String = "") {
        self.body = DataBuffer(data: Array(body.utf8))
        self.statusCode = statusCode
    }
    
    init(bytes: [UInt8]) {
        self.statusCode = (200, "OK")
        self.body = DataBuffer(data: bytes)
    }
}

extension Response {
    
    public static func NotFound(body: String) -> Response {
        return Response(statusCode: (404, "NOT FOUND"), body: body)
    }
    
    public static func InternalError(body: String) -> Response {
        return Response(statusCode: (500, "INTERNAL SERVER ERROR"), body: body)
    }
    
    public static func RedirectTo(url: String) -> Response {
        var resp = Response(statusCode: (302, "FOUND"))
        resp.headers["Location"] = url
        return resp
    }
}


protocol DataObservableType: class {
    func observe(data: [UInt8] -> (), end: ()->())
}

final class DataStream: DataObservableType {
    
    private var dataObservers: [[UInt8] -> ()]
    private var closeObservers: [() -> ()]
    private let closed: Bool = false
    
    
    class Sink {
        private let sendBytesFunc: [UInt8] -> ()
        private let sendCompleteFunc: () -> ()
        
        init(sendBytes: [UInt8] -> (), sendComplete: () -> ()) {
            self.sendBytesFunc = sendBytes
            self.sendCompleteFunc = sendComplete
        }
        
        func sendBytes(data: [UInt8]) {
            self.sendBytesFunc(data)
        }
        
        func close() {
            self.sendCompleteFunc()
        }
    }
    
    private init() {
        self.dataObservers = []
        self.closeObservers = []
    }
    
    private convenience init(closure: (sendBytes: [UInt8]->(), sendClose:()->()) -> ()) {
        self.init()
        closure( sendBytes: { data in
                for dataObserver in self.dataObservers {
                    dataObserver(data)
                }
            }, sendClose: {
                for closeObserver in self.closeObservers {
                    closeObserver()
                }
            })
    }
    
    static func createStream() -> (Sink, DataStream) {
        var sink: Sink!
        let stream = self.init() { sendBytes, sendComplete in
            sink = Sink(sendBytes: sendBytes, sendComplete: sendComplete)
        }
        return (sink, stream)
    }
    
    func observe(data: [UInt8] -> (), end: () -> ()) {
        if self.closed  == false {
            self.dataObservers.append(data)
            self.closeObservers.append(end)
        } else {
            end()
        }
    }
}


final class DataBuffer: DataObservableType {
    let buffer: [UInt8]
    
    init(data: [UInt8]) {
        self.buffer = data
    }
    
    func observe(data: [UInt8] -> (), end: () -> ()) {
        data(self.buffer)   //send containing data
        end()               //and then immediately end the stream
    }
    
}


enum MiddlewareResponse {
    case Terminal(Response)
    case Middleware(MiddlewareResponder -> MiddlewareResponse)
}

protocol MiddlewareResponder {
    func respond(to request: WebRequest) -> MiddlewareResponse
}

protocol Responder {
    func respond(to request: WebRequest) -> Response
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

final class AnyResponder: Responder {
    let repondHandler: WebRequest -> Response
    
    init(_ respondHandler: WebRequest -> Response) {
        self.repondHandler = respondHandler
    }
    
    func respond(to request: WebRequest) -> Response {
        return self.repondHandler(request)
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

final class LogMiddleware: MiddlewareResponder {
    let logFunc: String -> Void
    init(log: String -> Void ) {
        self.logFunc = log
    }
    
    func respond(to request: WebRequest) -> MiddlewareResponse {
        self.logFunc("Request: \(request.path)")
        func middlewareResponder(responder: MiddlewareResponder) -> MiddlewareResponse {
            return responder.respond(to: request)
        }
        return .Middleware(middlewareResponder)
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

