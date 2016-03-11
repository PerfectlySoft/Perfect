//
//  NetTCPSSL.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2015-09-23.
//	Copyright (C) 2015 PerfectlySoft, Inc.
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

import OpenSSL

private typealias passwordCallbackFunc = @convention(c) (UnsafeMutablePointer<Int8>, Int32, Int32, UnsafeMutablePointer<Void>) -> Int32

public class NetTCPSSL : NetTCP {
	
	public static var opensslVersionText : String {
		return OPENSSL_VERSION_TEXT
	}
	public static var opensslVersionNumber : Int {
		return OPENSSL_VERSION_NUMBER
	}
	
	public class X509 {
		
		private let ptr: UnsafeMutablePointer<OpenSSL.X509>
		
		init(ptr: UnsafeMutablePointer<OpenSSL.X509>) {
			self.ptr = ptr
		}
		
		deinit {
			X509_free(self.ptr)
		}
		
		public var publicKeyBytes: [UInt8] {
			let pk = X509_get_pubkey(self.ptr)
			let len = Int(i2d_PUBKEY(pk, nil))
			var mp = UnsafeMutablePointer<UInt8>()
			defer {
				free(mp)
				EVP_PKEY_free(pk)
			}
			
			i2d_PUBKEY(pk, &mp)
			
			var ret = [UInt8]()
			ret.reserveCapacity(len)
			for b in 0..<len {
				ret.append(mp[b])
			}
			return ret
		}
	}
	
	static var dispatchOnce = Threading.ThreadOnce()
	
	private var sharedSSLCtx = true
	private var sslCtx: UnsafeMutablePointer<SSL_CTX>?
	private var ssl: UnsafeMutablePointer<SSL>?
	
	public var keyFilePassword: String = "" {
		didSet {
			if !self.keyFilePassword.isEmpty {
				
				self.initSocket()

				let opaqueMe = UnsafeMutablePointer<Void>(Unmanaged.passUnretained(self).toOpaque())
				let callback: passwordCallbackFunc = {
					
					(buf, size, rwflag, userData) -> Int32 in

					let crl = Unmanaged<NetTCPSSL>.fromOpaque(COpaquePointer(userData)).takeUnretainedValue()
					return crl.passwordCallback(buf, size: size, rwflag: rwflag)
				}
				
				SSL_CTX_set_default_passwd_cb_userdata(self.sslCtx!, opaqueMe)
				SSL_CTX_set_default_passwd_cb(self.sslCtx!, callback)
			}
		}
	}
	
	public var peerCertificate: X509? {
		guard let ssl = self.ssl else {
			return nil
		}
		let cert = SSL_get_peer_certificate(ssl)
		if cert != nil {
			return X509(ptr: cert)
		}
		return nil
	}
	
	public var cipherList: [String] {
		get {
			var a = [String]()
			guard let ssl = self.ssl else {
				return a
			}
			var i = Int32(0)
			while true {
				let n = SSL_get_cipher_list(ssl, i)
				if n != nil {
					a.append(String.fromCString(n)!)
				} else {
					break
				}
				i += 1
			}
			return a
		}
		set(list) {
			let listStr = list.joinWithSeparator(",")
			if let ctx = self.sslCtx {
				if 0 == SSL_CTX_set_cipher_list(ctx, listStr) {
					print("SSL_CTX_set_cipher_list failed: \(self.errorStr(Int32(self.errorCode())))")
				}
			}
			if let ssl = self.ssl {
				if 0 == SSL_set_cipher_list(ssl, listStr) {
					print("SSL_CTX_set_cipher_list failed: \(self.errorStr(Int32(self.errorCode())))")
				}
			}
		}
	}
	
	public func setTmpDH(path: String) -> Bool {
		guard let ctx = self.sslCtx else {
			return false
		}
		
		let bio = BIO_new_file(path, "r")
		if bio == nil {
			return false
		}
		
		let dh = PEM_read_bio_DHparams(bio, nil, nil, nil)
		SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TMP_DH, 0, dh)
		DH_free(dh)
		BIO_free(bio)
		return true
	}
	
	public var usingSSL: Bool {
		return self.ssl != nil
	}
	
	public override init() {
		super.init()
		
		Threading.once(&NetTCPSSL.dispatchOnce) {
			SSL_library_init()
			ERR_load_crypto_strings()
			SSL_load_error_strings()
		}
	}
	
	deinit {
		if let ssl = self.ssl {
			SSL_shutdown(ssl)
			SSL_free(ssl)
		}
		if let sslCtx = self.sslCtx where self.sharedSSLCtx == false {
			SSL_CTX_free(sslCtx)
		}
	}
	
	func passwordCallback(buf:UnsafeMutablePointer<Int8>, size:Int32, rwflag:Int32) -> Int32 {
		let chars = self.keyFilePassword.utf8
		memmove(buf, self.keyFilePassword, chars.count + 1)
		return Int32(chars.count)
	}

	override public func initSocket() {
		super.initSocket()
		guard self.sslCtx == nil else {
			return
		}
		self.sslCtx = SSL_CTX_new(TLSv1_2_method())
		guard let sslCtx = self.sslCtx else {
			return
		}
		self.sharedSSLCtx = false
		SSL_CTX_ctrl(sslCtx, SSL_CTRL_SET_ECDH_AUTO, 1, nil)
		SSL_CTX_ctrl(sslCtx, SSL_CTRL_MODE, SSL_MODE_AUTO_RETRY, nil)
		SSL_CTX_ctrl(sslCtx, SSL_CTRL_OPTIONS, SSL_OP_ALL, nil)
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
			if sslErr != SSL_ERROR_SYSCALL {
				return sslErr == SSL_ERROR_WANT_READ || sslErr == SSL_ERROR_WANT_WRITE
			}
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
			[weak self] (fd:Int32, w:Int16, ud:AnyObject?) -> () in
			
			self?.writeBytes(nptr, wrote: wrote, length: length, completion: completion)
		}
		event.add()
	}
	
	public override func close() {
		if let ssl = self.ssl {
			SSL_shutdown(ssl)
			SSL_free(ssl)
			self.ssl = nil
		}
		if let sslCtx = self.sslCtx where self.sharedSSLCtx == false {
			SSL_CTX_free(sslCtx)
		}
		self.sslCtx = nil
		super.close()
	}
	
	public func beginSSL(closure: (Bool) -> ()) {
		self.beginSSL(5.0, closure: closure)
	}
	
	public func beginSSL(timeout: Double, closure: (Bool) -> ()) {
		guard self.fd.fd != invalidSocket else {
			closure(false)
			return
		}
		
		if self.ssl == nil {
			self.ssl = SSL_new(self.sslCtx!)
			SSL_set_fd(self.ssl!, self.fd.fd)
		}
		
		guard let ssl = self.ssl else {
			closure(false)
			return
		}
		
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
					[weak self] (fd:Int32, w:Int16, ud:AnyObject?) -> () in
					
					if (Int32(w) & EV_WRITE) != 0 {
						self?.beginSSL(timeout, closure: closure)
					} else {
						closure(false)
					}
				}
				event.add(timeout)
				return
			} else if sslErr == SSL_ERROR_WANT_READ {
				
				let event: LibEvent = LibEvent(base: LibEvent.eventBase, fd: fd.fd, what: EV_READ, userData: nil) {
					[weak self] (fd:Int32, w:Int16, ud:AnyObject?) -> () in
					
					if (Int32(w) & EV_READ) != 0 {
						self?.beginSSL(timeout, closure: closure)
					} else {
						closure(false)
					}
				}
				event.add(timeout)
				return
			} else {
				closure(false)
			}
		default:
			closure(false)
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
	
	public func setDefaultVerifyPaths() -> Bool {
		self.initSocket()
		guard let sslCtx = self.sslCtx else {
			return false
		}
		let r = SSL_CTX_set_default_verify_paths(sslCtx)
		return r == 1
	}
	
	public func setVerifyLocations(caFilePath: String, caDirPath: String) -> Bool {
		self.initSocket()
		guard let sslCtx = self.sslCtx else {
			return false
		}
		let r = SSL_CTX_load_verify_locations(sslCtx, caFilePath, caDirPath)
		return r == 1
	}
	
	public func useCertificateFile(cert: String) -> Bool {
		self.initSocket()
		guard let sslCtx = self.sslCtx else {
			return false
		}
		let r = SSL_CTX_use_certificate_file(sslCtx, cert, SSL_FILETYPE_PEM)
		return r == 1
	}
	
	public func useCertificateChainFile(cert: String) -> Bool {
		self.initSocket()
		guard let sslCtx = self.sslCtx else {
			return false
		}
		let r = SSL_CTX_use_certificate_chain_file(sslCtx, cert)
		return r == 1
	}
	
	public func usePrivateKeyFile(cert: String) -> Bool {
		self.initSocket()
		guard let sslCtx = self.sslCtx else {
			return false
		}
		let r = SSL_CTX_use_PrivateKey_file(sslCtx, cert, SSL_FILETYPE_PEM)
		return r == 1
	}
	
	public func checkPrivateKey() -> Bool {
		self.initSocket()
		guard let sslCtx = self.sslCtx else {
			return false
		}
		let r = SSL_CTX_check_private_key(sslCtx)
		return r == 1
	}
	
	override func makeFromFd(fd: Int32) -> NetTCP {
		return NetTCPSSL(fd: fd)
	}
	
	override public func forEachAccept(callBack: (NetTCP?) -> ()) {
		super.forEachAccept {
			[unowned self] (net:NetTCP?) -> () in
			
			if let netSSL = net as? NetTCPSSL {
				
				netSSL.sslCtx = self.sslCtx
				netSSL.ssl = SSL_new(self.sslCtx!)
				SSL_set_fd(netSSL.ssl!, netSSL.fd.fd)
				
				self.finishAccept(-1, net: netSSL, callBack: callBack)
			} else {
				callBack(net)
			}
		}
	}
	
	override public func accept(timeoutSeconds: Double, callBack: (NetTCP?) -> ()) throws {
		try super.accept(timeoutSeconds, callBack: {
			[unowned self] (net:NetTCP?) -> () in
			
			if let netSSL = net as? NetTCPSSL {
				
				netSSL.sslCtx = self.sslCtx
				netSSL.ssl = SSL_new(self.sslCtx!)
				SSL_set_fd(netSSL.ssl!, netSSL.fd.fd)
				
				self.finishAccept(timeoutSeconds, net: netSSL, callBack: callBack)
			} else {
				callBack(net)
			}
		})
	}
	
	func finishAccept(timeoutSeconds: Double, net: NetTCPSSL, callBack: (NetTCP?) -> ()) {
		let res = SSL_accept(net.ssl!)
		let sslErr = SSL_get_error(net.ssl!, res)
		if res == -1 {
			if sslErr == SSL_ERROR_WANT_WRITE {
				
				let event: LibEvent = LibEvent(base: LibEvent.eventBase, fd: net.fd.fd, what: EV_WRITE, userData: nil) {
					(fd:Int32, w:Int16, ud:AnyObject?) -> () in
					
					if (Int32(w) & EV_TIMEOUT) != 0 {
						callBack(nil)
					} else {
						self.finishAccept(timeoutSeconds, net: net, callBack: callBack)
					}
				}
				event.add(timeoutSeconds)
				
			} else if sslErr == SSL_ERROR_WANT_READ {
				
				let event: LibEvent = LibEvent(base: LibEvent.eventBase, fd: net.fd.fd, what: EV_READ, userData: nil) {
					(fd:Int32, w:Int16, ud:AnyObject?) -> () in
					
					if (Int32(w) & EV_TIMEOUT) != 0 {
						callBack(nil)
					} else {
						self.finishAccept(timeoutSeconds, net: net, callBack: callBack)
					}
				}
				event.add(timeoutSeconds)
				
			} else {
				callBack(nil)
			}
		} else {
			callBack(net)
		}
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
//			throw PerfectError.NetworkError(err, msg)
//		}
//	}

}

