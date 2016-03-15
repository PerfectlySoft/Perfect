//
//  MongoClient.swift
//  MongoDB
//
//  Created by Petr Pavlik on 2015-03-11.
//  Copyright © 2015 PerfectlySoft. All rights reserved.
//
//	This program is free software: you can redistribute it and/or modify
//	it under the terms of the GNU Affero General Public License as
//	published by the Free Software Foundation, either version 3 of the
//	License, or (at your option) any later version, as supplemented by the
//	Perfect Additional Terms.
//
//	This program is distributed in the hope that it will be useful,
//	but WITHOUT ANY WARRANTY; without even the implied warranty of
//	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//	GNU Affero General Public License, as supplemented by the
//	Perfect Additional Terms, for more details.
//
//	You should have received a copy of the GNU Affero General Public License
//	and the Perfect Additional Terms that immediately follow the terms and
//	conditions of the GNU Affero General Public License along with this
//	program. If not, see <http://www.perfect.org/AGPL_3_0_With_Perfect_Additional_Terms.txt>.
//

import libmongoc

public class MongoClientPool {
    
    var ptr: COpaquePointer
    
    public init(uri: String) {
        
        let uriPointer = mongoc_uri_new(uri)
        ptr = mongoc_client_pool_new(uriPointer)
    }
    
    deinit {
        mongoc_client_pool_destroy(ptr)
    }
    
    public func popClient() -> MongoClient {
        return MongoClient(pointer: mongoc_client_pool_pop(ptr))
    }
    
    public func pushClient(client: MongoClient) {
        mongoc_client_pool_push(ptr, client.ptr)
        client.ptr = nil
    }
    
    public func executeBlock(@noescape block: (client: MongoClient) -> Void) {
        let client = popClient()
        block(client: client)
        pushClient(client)
    }
}