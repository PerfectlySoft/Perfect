//
//  NetTCPSSL.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2015-09-23.
//
//

import OpenSSL

public class NetTCPSSL : NetTCP {
	
	static var dispatchOnce: dispatch_once_t = 0
	
	var sslCtx: UnsafeMutablePointer<SSL_CTX>?
	var ssl: UnsafeMutablePointer<SSL>?
	
	var keyFilePassword: String = "" {
		didSet {
			if !self.keyFilePassword.isEmpty {
				
				self.initSocket()
				
//				SSL_CTX_set_default_passwd_cb(self.sslCtx!, passwordCallback)
				
			}
		}
	}
	
	public var usingSSL: Bool {
		return self.sslCtx != nil
	}
	
	public override init() {
		super.init()
		
		dispatch_once(&NetTCPSSL.dispatchOnce) {
			SSL_library_init()
			ERR_load_crypto_strings()
			SSL_load_error_strings()
		}
	}
	
	func passwordCallback(buf:UnsafeMutablePointer<Int8>, size:Int32, rwflag:Int32, userData:UnsafeMutablePointer<Void>) -> Int32 {
		let chars = self.keyFilePassword.utf8
		memmove(buf, self.keyFilePassword, chars.count + 1)
		return Int32(chars.count)
	}

	override public func initSocket() {
		super.initSocket()
		guard self.sslCtx == nil else {
			return
		}
		self.sslCtx = SSL_CTX_new(TLSv1_method())
		guard let sslCtx = self.sslCtx else {
			return
		}
		guard sslCtx != nil else {
			return
		}
		SSL_CTX_ctrl(sslCtx, SSL_CTRL_MODE, SSL_MODE_AUTO_RETRY, nil)
		SSL_CTX_ctrl(sslCtx, SSL_CTRL_OPTIONS, SSL_OP_ALL, nil)
		
		self.ssl = SSL_new(sslCtx)
	}
	
	public func errorCode() -> UInt {
		let err = ERR_get_error()
		return err
	}
	
	public func sslErrorCode(resultCode: Int32) -> Int32 {
		if let ssl = self.ssl {
			let err = SSL_get_error(ssl, resultCode)
			return err
		}
		return -1
	}
	
	public func errorStr(errorCode: Int32) -> String {
		let maxLen = 1024
		let buf = UnsafeMutablePointer<Int8>.alloc(maxLen)
		defer {
			buf.destroy() ; buf.dealloc(maxLen)
		}
		ERR_error_string_n(UInt(errorCode), buf, maxLen)
		let ret = String.fromCString(buf) ?? ""
		return ret
	}
	
	public func reasonErrorStr(errorCode: Int32) -> String {
		let buf = ERR_reason_error_string(UInt(errorCode))
		let ret = String.fromCString(buf) ?? ""
		return ret
	}
	
	override func isEAgain(err: Int) -> Bool {
		if err == -1 && self.usingSSL {
			let sslErr = SSL_get_error(self.ssl!, Int32(err))
			return sslErr == SSL_ERROR_WANT_READ || sslErr == SSL_ERROR_WANT_WRITE
		}
		return super.isEAgain(err)
	}
	
	override func evWhatFor(operation: Int32) -> Int32 {
		if self.usingSSL {
			let sslErr = SSL_get_error(self.ssl!, -1)
			if sslErr == SSL_ERROR_WANT_READ {
				return EV_READ
			} else if sslErr == SSL_ERROR_WANT_WRITE {
				return EV_WRITE
			}
		}
		return super.evWhatFor(operation)
	}
	
	override func recv(buf: UnsafeMutablePointer<Void>, count: Int) -> Int {
		if self.usingSSL {
			let i = Int(SSL_read(self.ssl!, buf, Int32(count)))
			return i
		}
		return super.recv(buf, count: count)
	}
	
	override func send(buf: UnsafePointer<Void>, count: Int) -> Int {
		if self.usingSSL {
			let i = Int(SSL_write(self.ssl!, buf, Int32(count)))
			return i
		}
		return super.send(buf, count: count)
	}
	
	override func readBytesFullyIncomplete(into: ReferenceBuffer, read: Int, remaining: Int, timeoutSeconds: Double, completion: ([UInt8]?) -> ()) {
		guard usingSSL else {
			return super.readBytesFullyIncomplete(into, read: read, remaining: remaining, timeoutSeconds: timeoutSeconds, completion: completion)
		}
		var what = EV_WRITE
		let sslErr = SSL_get_error(self.ssl!, -1)
		if sslErr == SSL_ERROR_WANT_READ {
			what = EV_READ
		}
		
		let event: LibEvent = LibEvent(base: LibEvent.eventBase, fd: fd.fd, what: what, userData: nil) {
			(fd:Int32, w:Int16, ud:AnyObject?) -> () in
			
			if (Int32(w) & EV_TIMEOUT) == 0 {
				self.readBytesFully(into, read: read, remaining: remaining, timeoutSeconds: timeoutSeconds, completion: completion)
			} else {
				completion(nil) // timeout or error
			}
		}
		event.add()
	}
	
	override func writeBytesIncomplete(nptr: UnsafeMutablePointer<UInt8>, wrote: Int, length: Int, completion: (Int) -> ()) {
		guard usingSSL else {
			return super.writeBytesIncomplete(nptr, wrote: wrote, length: length, completion: completion)
		}
		var what = EV_WRITE
		let sslErr = SSL_get_error(self.ssl!, -1)
		if sslErr == SSL_ERROR_WANT_READ {
			what = EV_READ
		}
		
		let event: LibEvent = LibEvent(base: LibEvent.eventBase, fd: fd.fd, what: what, userData: nil) {
			(fd:Int32, w:Int16, ud:AnyObject?) -> () in
			
			self.writeBytes(nptr, wrote: wrote, length: length, completion: completion)
		}
		event.add()
	}
	
	public override func close() {
		if let ssl = self.ssl {
			SSL_shutdown(ssl)
			SSL_free(ssl)
			self.ssl = nil
		}
		if let sslCtx = self.sslCtx {
			SSL_CTX_free(sslCtx)
			self.sslCtx = nil
		}
		super.close()
	}
	
	public func beginSSL(closure: (Bool) -> ()) {
		self.beginSSL(5.0, closure: closure)
	}
	
	public func beginSSL(timeout: Double, closure: (Bool) -> ()) {
		guard self.fd.fd != INVALID_SOCKET else {
			closure(false)
			return
		}
		guard let sslCtx = self.sslCtx else {
			closure(false)
			return
		}
		guard sslCtx != nil else {
			closure(false)
			return
		}
		guard let ssl = self.ssl else {
			closure(false)
			return
		}
		guard ssl != nil else {
			closure(false)
			return
		}
		
		self.setConnectState()
		
		let res = SSL_connect(ssl)
		switch res {
		case 1:
			closure(true)
		case 0:
			closure(false)
		case -1:
			let sslErr = SSL_get_error(ssl, res)
			if sslErr == SSL_ERROR_WANT_WRITE {
				
				let event: LibEvent = LibEvent(base: LibEvent.eventBase, fd: fd.fd, what: EV_WRITE, userData: nil) {
					(fd:Int32, w:Int16, ud:AnyObject?) -> () in
					
					if (Int32(w) & EV_WRITE) != 0 {
						self.beginSSL(timeout, closure: closure)
					} else {
						closure(false)
					}
				}
				event.add(timeout)
				return
			} else if sslErr == SSL_ERROR_WANT_READ {
				
				let event: LibEvent = LibEvent(base: LibEvent.eventBase, fd: fd.fd, what: EV_READ, userData: nil) {
					(fd:Int32, w:Int16, ud:AnyObject?) -> () in
					
					if (Int32(w) & EV_READ) != 0 {
						self.beginSSL(timeout, closure: closure)
					} else {
						closure(false)
					}
				}
				event.add(timeout)
				return
			}
		default:
			()
		}
	}
	
	public func endSSL() {
		if let ssl = self.ssl {
			SSL_free(ssl)
			self.ssl = nil
		}
		if let sslCtx = self.sslCtx {
			SSL_CTX_free(sslCtx)
			self.sslCtx = nil
		}
	}
	
	public func shutdown() {
		if let ssl = self.ssl {
			SSL_shutdown(ssl)
		}
	}
	
	public func setConnectState() {
		if let ssl = self.ssl {
			SSL_set_connect_state(ssl)
		}
	}
	
	public func setAcceptState() {
		if let ssl = self.ssl {
			SSL_set_accept_state(ssl)
		}
	}
	
	public func setVerifyLocations(caFilePath: String, caDirPath: String) -> Bool {
		self.initSocket()
		guard let sslCtx = self.sslCtx else {
			return false
		}
		let r = SSL_CTX_load_verify_locations(sslCtx, caFilePath, caDirPath)
		return r == 0
	}
	
	public func useCertificateChainFile(cert: String) -> Bool {
		self.initSocket()
		guard let sslCtx = self.sslCtx else {
			return false
		}
		let r = SSL_CTX_use_certificate_chain_file(sslCtx, cert)
		return r == 0
	}
	
	public func usePrivateKeyFile(cert: String) -> Bool {
		self.initSocket()
		guard let sslCtx = self.sslCtx else {
			return false
		}
		let r = SSL_CTX_use_PrivateKey_file(sslCtx, cert, SSL_FILETYPE_PEM)
		return r == 0
	}
	
//	private func throwSSLNetworkError(err: Int32) throws {
//		if err != 0 {
//			let maxLen = 1024
//			let buf = UnsafeMutablePointer<Int8>.alloc(maxLen)
//			defer {
//				buf.destroy() ; buf.dealloc(maxLen)
//			}
//			ERR_error_string_n(self.sslErrorCode, buf, maxLen)
//			let msg = String.fromCString(buf) ?? ""
//			
//			print("SSL NetworkError: \(err) \(msg)")
//			
//			throw LassoError.NetworkError(err, msg)
//		}
//	}

}

