//
//  HTTP2PrefaceValidator.swift
//  PerfectHTTPServer
//
//  Created by Kyle Jessup on 2017-06-22.
//
//

import PerfectNet

let prefaceBytes = Array(http2ConnectionPreface.utf8)

struct HTTP2PrefaceValidator {
	init(_ net: NetTCP, timeoutSeconds: Double, callback: @escaping () -> ()) {
		net.readBytesFully(count: prefaceBytes.count, timeoutSeconds: timeoutSeconds) { bytes in
			guard let b = bytes, b == prefaceBytes else {
				return net.close()
			}
			callback()
		}
	}
}
