//
//  Response.swift
//  PerfectLib
//
//  Created by Sergii Gavryliuk on 2016-05-08.
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
