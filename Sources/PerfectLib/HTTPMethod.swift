//
//  HTTPMethod.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2016-06-20.
//	Copyright (C) 2016 PerfectlySoft, Inc.
//
//===----------------------------------------------------------------------===//
//
// This source file is part of the Perfect.org open source project
//
// Copyright (c) 2015 - 2016 PerfectlySoft Inc. and the Perfect project authors
// Licensed under Apache License v2.0
//
// See http://perfect.org/licensing.html for license information
//
//===----------------------------------------------------------------------===//
//

/// HTTP request method types
public enum HTTPMethod: Hashable, CustomStringConvertible {
    /// OPTIONS
    case options,
    /// GET
    get,
    /// HEAD
    head,
    /// POST
    post,
    /// PUT
    put,
    /// DELETE
    delete,
    /// TRACE
    trace,
    /// CONNECT
    connect,
    /// Any unaccounted for or custom method
    custom(String)
    
    public static func from(string: String) -> HTTPMethod {
        
        switch string {
        case "OPTIONS": return .options
        case "GET":     return .get
        case "HEAD":    return .head
        case "POST":    return .post
        case "PUT":     return .put
        case "DELETE":  return .delete
        case "TRACE":   return .trace
        case "CONNECT": return .connect
        default:        return .custom(string)
        }
    }
    
    /// Method String hash value
    public var hashValue: Int {
        return self.description.hashValue
    }
    
    /// The method as a String
    public var description: String {
        switch self {
        case .options:  return "OPTIONS"
        case .get:      return "GET"
        case .head:     return "HEAD"
        case .post:     return "POST"
        case .put:      return "PUT"
        case .delete:   return "DELETE"
        case .trace:    return "TRACE"
        case .connect:  return "CONNECT"
        case .custom(let s): return s
        }
    }
}

/// Compare two HTTP methods
public func == (lhs: HTTPMethod, rhs: HTTPMethod) -> Bool {
    return lhs.description == rhs.description
}
