//
//  BSONObjectId.swift
//  MongoDB
//
//  Created by Petr Pavlik on 13/03/16.
//  Copyright © 2016 PerfectlySoft. All rights reserved.
//

import libmongoc

public class BSONObjectId {
    
    let oid: UnsafePointer<bson_oid_t>
    
    init(oid: UnsafePointer<bson_oid_t>) {
        self.oid = oid
    }
    
    public var hashValue: Int {
        return Int(bson_oid_hash(oid))
    }
    
    /*public func ==(lhs: Self, rhs: Self) -> Bool {
        return lhs.hashValue == rhs.hashValue
    }*/
    
    public var asString: String? {
        let cstring = UnsafeMutablePointer<Int8>.alloc(25)
        defer {
            cstring.dealloc(25)
        }
        bson_oid_to_string(oid, cstring)
        return String.fromCString(cstring)
    }
    
    //TODO: expose generation time
}