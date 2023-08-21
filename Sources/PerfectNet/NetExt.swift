//
//  NetExt.swift
//  
//
//  Created by Rocky Wei on 2023-08-21.
//

import Foundation

@available(macOS 10.15.0, *)
public extension NetTCP {
    /// Read the indicated number of bytes and deliver them concurrently.
    /// - parameter count: The number of bytes to read
    /// - parameter timeoutSeconds: The number of seconds to wait for the requested number of bytes. A timeout value of negative one indicates that the request should have no timeout.
    /// - returns: If the timeout occurs before the requested number of bytes have been read, an empty array will be delivered to the callback.
    /// If an error or disconnection occurs then a nil object will be delivered.
    func readBytesFullyWithContinuation(count: Int, timeoutSeconds: Double) async -> [UInt8]? {
        return await withCheckedContinuation { continuation in
            readBytesFully(count: count, timeoutSeconds: timeoutSeconds) { data in
                continuation.resume(returning: data)
            }
        }
    }

    /// Read up to the indicated number of bytes and deliver them concurrently
    /// - parameter count: The maximum number of bytes to read.
    /// - returns: If an error occurs during the read then a nil object will be passed, otherwise, the immediately available number of bytes, which may be zero, will be passed.
    func readSomeBytes(count: Int) async -> [UInt8]? {
        return await withCheckedContinuation { continuation in
            readSomeBytes(count: count) { data in
                continuation.resume(returning: data)
            }
        }
    }

    /// Write the string and return the number of bytes which were written.
    /// - parameter s: The string to write. The string will be written based on its UTF-8 encoding.
    /// - returns: The number of bytes which were successfuly written, which may be zero.
    func writeWithContinuation(string: String) async -> Int {
        return await withCheckedContinuation { continuation in
            write(string: string) { written in
                continuation.resume(returning: written)
            }
        }
    }

    /// Write the indicated bytes and return the number of bytes which were written.
    /// - parameter bytes: The array of UInt8 to write.
    /// - returns: The number of bytes which were successfuly written, which may be zero.
    func writeWithContinuation(bytes: [UInt8]) async -> Int {
        return await withCheckedContinuation { continuation in
            write(bytes: bytes) { written in
                continuation.resume(returning: written)
            }
        }
    }

    /// Write the indicated bytes and return the number of bytes which were written.
    /// - parameter bytes: The array of UInt8 to write.
    /// - parameter offsetBy: The offset within `bytes` at which to begin writing.
    /// - parameter count: The number of bytes to write.
    /// - returns: The number of bytes which were successfuly written, which may be zero.
    func writeWithContinuation(bytes: [UInt8], offsetBy: Int, count: Int) async -> Int {
        return await withCheckedContinuation { continuation in
            write(bytes: bytes, offsetBy: offsetBy, count: count) { written in
                continuation.resume(returning: written)
            }
        }
    }

    /// Connect to the indicated server
    /// - parameter address: The server's address, expressed as a string.
    /// - parameter port: The port on which to connect.
    /// - parameter timeoutSeconds: The number of seconds to wait for the connection to complete. A timeout of negative one indicates that there is no timeout.
    /// - returns: If the connection completes successfully then the current NetTCP instance will be passed to the callback, otherwise, a nil object will be passed.
    /// - returns: `PerfectError.NetworkError`
    func connectWithContinuation(address: String, port: UInt16, timeoutSeconds: Double) async throws -> NetTCP? {
        return try await withCheckedThrowingContinuation { continuation in
            do {
                try connect(address: address, port: port, timeoutSeconds: timeoutSeconds) {
                    continuation.resume(returning: $0)
                }
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }

    /// Connect to the indicated server
    /// - parameter address: The server's address, expressed as a string.
    /// - parameter port: The port on which to connect.
    /// - parameter timeoutSeconds: The number of seconds to wait for the connection to complete. A timeout of negative one indicates that there is no timeout.
    /// - returns:. If the connection completes successfully then the current NetTCP instance will be passed to the callback, otherwise, a nil object will be passed.
    /// - throws: `PerfectError.NetworkError`
    func acceptWithContinuation(timeoutSeconds: Double) async throws -> NetTCP? {
        return try await withCheckedThrowingContinuation { continuation in
            do {
                try accept(timeoutSeconds: timeoutSeconds) {
                    continuation.resume(returning: $0)
                }
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }
}
