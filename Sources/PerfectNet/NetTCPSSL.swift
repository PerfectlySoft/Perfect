//
//  NetTCPSSL.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2015-09-23.
//	Copyright (C) 2015 PerfectlySoft, Inc.
//
// ===----------------------------------------------------------------------===//
//
// This source file is part of the Perfect.org open source project
//
// Copyright (c) 2015 - 2016 PerfectlySoft Inc. and the Perfect project authors
// Licensed under Apache License v2.0
//
// See http://perfect.org/licensing.html for license information
//
// ===----------------------------------------------------------------------===//
//

import COpenSSL
import PerfectCrypto

#if os(Linux)
	import SwiftGlibc
#else
	import Darwin
#endif

// swiftlint:disable type_name
private typealias passwordCallbackFunc = @convention(c) (UnsafeMutablePointer<Int8>?, Int32, Int32, UnsafeMutableRawPointer?) -> Int32
public typealias VerifyCACallbackFunc = @convention (c) (Int32, UnsafeMutablePointer<X509_STORE_CTX>?) -> Int32

public struct OpenSSLVerifyMode: OptionSet {
  public let rawValue: Int32
  public init(rawValue: Int32) {
    self.rawValue = rawValue
  }
  public static let sslVerifyNone = OpenSSLVerifyMode(rawValue: SSL_VERIFY_NONE)
  public static let sslVerifyPeer = OpenSSLVerifyMode(rawValue: SSL_VERIFY_PEER)
  public static let sslVerifyFailIfNoPeerCert = OpenSSLVerifyMode(rawValue: SSL_VERIFY_FAIL_IF_NO_PEER_CERT)
  public static let sslVerifyClientOnce = OpenSSLVerifyMode(rawValue: SSL_VERIFY_CLIENT_ONCE)
  public static let sslVerifyPeerWithFailIfNoPeerCert: OpenSSLVerifyMode = [.sslVerifyPeer, .sslVerifyFailIfNoPeerCert]
  public static let sslVerifyPeerClientOnce: OpenSSLVerifyMode = [.sslVerifyPeer, .sslVerifyClientOnce]
  public static let sslVerifyPeerWithFailIfNoPeerCertClientOnce: OpenSSLVerifyMode = [.sslVerifyPeer, .sslVerifyFailIfNoPeerCert, .sslVerifyClientOnce]
}

public enum TLSMethod {
	case tlsV1
	case tlsV1_1
	case tlsV1_2
}

private class AutoFreeSSLCTX {
	let sslCtx: UnsafeMutablePointer<SSL_CTX>?
	init(_ sslCtx: UnsafeMutablePointer<SSL_CTX>?) {
		self.sslCtx = sslCtx
	}
	deinit {
		if let sslCtx = self.sslCtx {
			SSL_CTX_free(sslCtx)
		}
	}
}

public class NetTCPSSL: NetTCP {

	public static var opensslVersionText: String {
		return OPENSSL_VERSION_TEXT
	}
	public static var opensslVersionNumber: Int {
		return OPENSSL_VERSION_NUMBER
	}

	public class X509 {

		private let ptr: UnsafeMutablePointer<COpenSSL.X509>

		init(ptr: UnsafeMutablePointer<COpenSSL.X509>) {
			self.ptr = ptr
		}

		deinit {
			X509_free(self.ptr)
		}

		public var publicKeyBytes: [UInt8] {
			let pk = X509_get_pubkey(self.ptr)
			let len = Int(i2d_PUBKEY(pk, nil))
			var mp = UnsafeMutablePointer<UInt8>(nil as OpaquePointer?)

			i2d_PUBKEY(pk, &mp)

			var ret = [UInt8]()
			guard let ensure = mp else {
				return ret
			}
			defer {
				free(mp)
				EVP_PKEY_free(pk)
			}

			ret.reserveCapacity(len)
			for b in 0..<len {
				ret.append(ensure[b])
			}

			return ret
		}
	}

	static var sslCtxALPNBufferIndex = 0 as Int32
	static var sslCtxALPNBufferSizeIndex = 0 as Int32
	static var sslAcceptingNetIndex = 0 as Int32
    static var initOnce: Bool = {
		guard PerfectCrypto.isInitialized else {
			return false
		}
        copenssl_SSL_library_init()
		sslCtxALPNBufferIndex = SSL_CTX_get_ex_new_index(0, nil, nil, nil, { (_: UnsafeMutableRawPointer?, p2: UnsafeMutableRawPointer?, _: UnsafeMutablePointer<CRYPTO_EX_DATA>?, _: Int32, _: Int, _: UnsafeMutableRawPointer?) in
			if let p2 = p2 {
				copenssl_CRYPTO_free(p2, #file, #line)
			}
		})
		sslCtxALPNBufferSizeIndex = SSL_CTX_get_ex_new_index(0, nil, nil, nil, nil)
		sslAcceptingNetIndex = SSL_get_ex_new_index(0, nil, nil, nil, nil)
        return true
    }()

	fileprivate var trackCtx: AutoFreeSSLCTX?
	fileprivate var sslCtx: UnsafeMutablePointer<SSL_CTX>? {
		get { return trackCtx?.sslCtx }
		set { trackCtx = AutoFreeSSLCTX(newValue) }
	}
	fileprivate var ssl: UnsafeMutablePointer<SSL>?
	public var tlsMethod: TLSMethod = .tlsV1_2
	fileprivate var sniContextMap = [String: AutoFreeSSLCTX]()

	public var keyFilePassword: String = ""
	public var peerCertificate: X509? {
		guard let ssl = self.ssl else {
			return nil
		}
		guard let cert = SSL_get_peer_certificate(ssl) else {
			return nil
		}
		return X509(ptr: cert)
	}

	public var cipherList: [String] {
		get {
			var a = [String]()
			guard let ssl = self.ssl else {
				return a
			}
			var i = Int32(0)
			while true {
				guard let n = SSL_get_cipher_list(ssl, i) else {
					break
				}
				a.append(String(validatingUTF8: n)!)
				i += 1
			}
			return a
		}
		set(list) {
			let listStr = list.joined(separator: ",")
			if let ctx = self.sslCtx {
				if 0 == SSL_CTX_set_cipher_list(ctx, listStr) {
					print("SSL_CTX_set_cipher_list failed: \(self.errorStr(forCode: Int32(self.errorCode())))")
				}
			}
			if let ssl = self.ssl {
				if 0 == SSL_set_cipher_list(ssl, listStr) {
					print("SSL_CTX_set_cipher_list failed: \(self.errorStr(forCode: Int32(self.errorCode())))")
				}
			}
		}
	}

	public var initializedCallback: ((NetTCPSSL) -> ())?

	public func setTmpDH(path: String) -> Bool {
		guard let ctx = self.sslCtx,
			let bio = BIO_new_file(path, "r") else {
			return false
		}
		defer {
			BIO_free(bio)
		}
		guard let dh = PEM_read_bio_DHparams(bio, nil, nil, nil) else {
			return false
		}
		defer {
			DH_free(dh)
		}
		SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TMP_DH, 0, dh)
		return true
	}

	public var usingSSL: Bool {
		return self.ssl != nil
	}

	public override init() {
		super.init()
		_ = NetTCPSSL.initOnce
	}

	func passwordCallback(_ buf: UnsafeMutablePointer<Int8>, size: Int32, rwflag: Int32) -> Int32 {
		let chars = self.keyFilePassword.utf8
		memmove(buf, self.keyFilePassword, chars.count)
		buf[chars.count] = 0
		return Int32(chars.count)
	}

	fileprivate func makeSSLCTX() -> UnsafeMutablePointer<SSL_CTX>? {
		let newSslCtx: UnsafeMutablePointer<SSL_CTX>?
		switch self.tlsMethod {
		case .tlsV1_2: newSslCtx = SSL_CTX_new(TLSv1_2_method())
		case .tlsV1_1: newSslCtx = SSL_CTX_new(TLSv1_1_method())
		case .tlsV1: newSslCtx = SSL_CTX_new(TLSv1_method())
		}

		guard let sslCtx = newSslCtx else {
			return nil
		}
		copenssl_SSL_CTX_set_options(sslCtx)
		return sslCtx
	}

	override public func initSocket(family: Int32) {
		super.initSocket(family: family)
		guard self.sslCtx == nil else {
			return
		}
		self.sslCtx = makeSSLCTX()
		guard nil != self.sslCtx else {
			return
		}
		initializedCallback?(self)
		if !keyFilePassword.isEmpty {
			let opaqueMe = Unmanaged.passUnretained(self).toOpaque()
			let callback: passwordCallbackFunc = { (buf, size, rwflag, userData) -> Int32 in

				guard let userDataCheck = userData, let bufCheck = buf else {
					return 0
				}
				let crl = Unmanaged<NetTCPSSL>.fromOpaque(UnsafeMutableRawPointer(userDataCheck)).takeUnretainedValue()
				return crl.passwordCallback(bufCheck, size: size, rwflag: rwflag)
			}
			SSL_CTX_set_default_passwd_cb_userdata(self.sslCtx!, opaqueMe)
			SSL_CTX_set_default_passwd_cb(self.sslCtx!, callback)
		}
	}

	public func errorCode() -> UInt {
		let err = ERR_get_error()
		return err
	}

	public func sslErrorCode(resultCode code: Int32) -> Int32 {
		if let ssl = self.ssl {
			let err = SSL_get_error(ssl, code)
			return err
		}
		return -1
	}

	public func errorStr(forCode errorCode: Int32) -> String {
		let maxLen = 1024
        let buf = UnsafeMutablePointer<Int8>.allocate(capacity: maxLen)
		defer {
			buf.deallocate()
		}
		ERR_error_string_n(UInt(errorCode), buf, maxLen)
		let ret = String(validatingUTF8: buf) ?? ""
		return ret
	}

	public func reasonErrorStr(errorCode: Int32) -> String {
		guard let buf = ERR_reason_error_string(UInt(errorCode)) else {
			return ""
		}
		let ret = String(validatingUTF8: buf) ?? ""
		return ret
	}

	override func isEAgain(err er: Int) -> Bool {
		if er == -1 && self.usingSSL {
			let sslErr = SSL_get_error(self.ssl!, Int32(er))
			if sslErr != SSL_ERROR_SYSCALL {
				return sslErr == SSL_ERROR_WANT_READ || sslErr == SSL_ERROR_WANT_WRITE
			}
		}
		return super.isEAgain(err: er)
	}

	override func recv(into buf: UnsafeMutableRawPointer, count: Int) -> Int {
		if self.usingSSL {
			let i = Int(SSL_read(self.ssl!, buf, Int32(count)))
			return i
		}
		return super.recv(into: buf, count: count)
	}

	override func send(_ buf: [UInt8], offsetBy: Int, count: Int) -> Int {
		return buf.withUnsafeBytes {
			let ptr = $0.baseAddress?.advanced(by: offsetBy)
			if self.usingSSL {
				let i = Int(SSL_write(self.ssl!, ptr, Int32(count)))
				return i
			}
			return super.send(buf, offsetBy: offsetBy, count: count)
		}
	}

	override func readBytesFullyIncomplete(into to: ReferenceBuffer, read: Int, remaining: Int, timeoutSeconds: Double, completion: @escaping ([UInt8]?) -> ()) {
		guard usingSSL else {
			return super.readBytesFullyIncomplete(into: to, read: read, remaining: remaining, timeoutSeconds: timeoutSeconds, completion: completion)
		}
		var what = NetEvent.Filter.write
		let sslErr = SSL_get_error(self.ssl!, -1)
		if sslErr == SSL_ERROR_WANT_READ {
			what = NetEvent.Filter.read
		}

		NetEvent.add(socket: fd.fd, what: what, timeoutSeconds: NetEvent.noTimeout) { _, w in

			if case .timer = w {
				completion(nil) // timeout or error
			} else {
				self.readBytesFully(into: to, read: read, remaining: remaining, timeoutSeconds: timeoutSeconds, completion: completion)
			}
		}
	}

	override func writeIncomplete(bytes: [UInt8], offsetBy: Int, count: Int, completion: @escaping (Int) -> ()) {
		guard usingSSL else {
			return super.writeIncomplete(bytes: bytes, offsetBy: offsetBy, count: count, completion: completion)
		}
		var what = NetEvent.Filter.write
		let sslErr = SSL_get_error(self.ssl!, -1)
		if sslErr == SSL_ERROR_WANT_READ {
			what = NetEvent.Filter.read
		}

		NetEvent.add(socket: fd.fd, what: what, timeoutSeconds: NetEvent.noTimeout) { [weak self] _, _ in
			self?.write(bytes: bytes, offsetBy: offsetBy, count: count, completion: completion)
		}
	}

	public override func close() {
		if let ssl = self.ssl {
			SSL_shutdown(ssl)
			SSL_free(ssl)
			self.ssl = nil
		}
		self.sslCtx = nil
		super.close()
	}

	public func beginSSL(closure: @escaping (Bool) -> ()) {
		self.beginSSL(timeoutSeconds: 5.0, closure: closure)
	}

	public func beginSSL(timeoutSeconds timeout: Double, closure: @escaping (Bool) -> ()) {
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
		SSL_set_ex_data(ssl, NetTCPSSL.sslAcceptingNetIndex, Unmanaged.passUnretained(self).toOpaque())

		let res = SSL_connect(ssl)
		switch res {
		case 1:
			closure(true)
		case 0:
			closure(false)
		case -1:
			let sslErr = SSL_get_error(ssl, res)
			if sslErr == SSL_ERROR_WANT_WRITE {

				NetEvent.add(socket: fd.fd, what: .write, timeoutSeconds: timeout) { [weak self] _, w in

					if case .write = w {
						self?.beginSSL(timeoutSeconds: timeout, closure: closure)
					} else {
						closure(false)
					}
				}
				return
			} else if sslErr == SSL_ERROR_WANT_READ {

				NetEvent.add(socket: fd.fd, what: .read, timeoutSeconds: timeout) { [weak self] _, w in

					if case .read = w {
						self?.beginSSL(timeoutSeconds: timeout, closure: closure)
					} else {
						closure(false)
					}
				}
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

	override public func shutdown() {
		if let ssl = self.ssl {
			SSL_shutdown(ssl)
		}
		super.shutdown()
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

	override func makeFromFd(_ fd: Int32) -> NetTCP {
		return NetTCPSSL(fd: fd)
	}

	override public func listen(backlog: Int32 = 128) {
		enableSNIServer()
		super.listen(backlog: backlog)
	}

	override public func connect(address addrs: String, port: UInt16, timeoutSeconds: Double, callBack: @escaping (NetTCP?) -> ()) throws {
		_ = setDefaultVerifyPaths()
		try super.connect(address: addrs, port: port, timeoutSeconds: timeoutSeconds) { net in
			guard let netSSL = net as? NetTCPSSL else {
				return callBack(net)
			}
			netSSL.beginSSL { success in
				guard success else {
					netSSL.close()
					return callBack(nil)
				}
				callBack(netSSL)
			}
		}
	}

	private func accepted(_ net: NetTCP?, callBack: @escaping (NetTCP?) -> ()) {
		if let netSSL = net as? NetTCPSSL {
			netSSL.trackCtx = self.trackCtx
			netSSL.ssl = SSL_new(self.sslCtx!)
			SSL_set_fd(netSSL.ssl!, netSSL.fd.fd)
			self.finishAccept(timeoutSeconds: -1, net: netSSL, callBack: callBack)
		} else {
			callBack(net)
		}
	}

	override public func forEachAccept(callBack: @escaping (NetTCP?) -> ()) {
		super.forEachAccept { [unowned self] (net: NetTCP?) -> () in
			self.accepted(net, callBack: callBack)
		}
	}

	override public func accept(timeoutSeconds timeout: Double, callBack: @escaping (NetTCP?) -> ()) throws {
		try super.accept(timeoutSeconds: timeout, callBack: { [unowned self] (net: NetTCP?) -> () in
			self.accepted(net, callBack: callBack)
		})
	}

	func finishAccept(timeoutSeconds timeout: Double, net: NetTCPSSL, callBack: @escaping (NetTCP?) -> ()) {
		SSL_set_ex_data(net.ssl!, NetTCPSSL.sslAcceptingNetIndex, Unmanaged.passUnretained(net).toOpaque())
		let res = SSL_accept(net.ssl!)
		let sslErr = SSL_get_error(net.ssl!, res)
		if res == -1 {
			if sslErr == SSL_ERROR_WANT_WRITE {

				NetEvent.add(socket: net.fd.fd, what: .write, timeoutSeconds: timeout) { [weak self] _, w in

					if case .timer = w {
						callBack(nil)
					} else {
						self?.finishAccept(timeoutSeconds: timeout, net: net, callBack: callBack)
					}
				}

			} else if sslErr == SSL_ERROR_WANT_READ {

				NetEvent.add(socket: net.fd.fd, what: .read, timeoutSeconds: timeout) { [weak self] _, w in

					if case .timer = w {
						callBack(nil)
					} else {
						self?.finishAccept(timeoutSeconds: timeout, net: net, callBack: callBack)
					}
				}

			} else {
				callBack(nil)
			}
		} else {
			callBack(net)
		}
	}
}

extension NetTCPSSL {

	fileprivate func getCtx(forHost: String?) -> AutoFreeSSLCTX? {
		guard let forHost = forHost else {
			return trackCtx
		}
		let auto: AutoFreeSSLCTX
		if let foundSSLCtx = sniContextMap[forHost] {
			auto = foundSSLCtx
		} else {
			let newCtx = makeSSLCTX()
			auto = AutoFreeSSLCTX(newCtx)
			sniContextMap[forHost] = auto
		}
		return auto
	}

	public func setDefaultVerifyPaths(forHost: String? = nil) -> Bool {
		guard let sslCtx = getCtx(forHost: forHost)?.sslCtx else {
			return false
		}
		let r = SSL_CTX_set_default_verify_paths(sslCtx)
		return r == 1
	}

	public func setVerifyLocations(caFilePath: String, caDirPath: String, forHost: String? = nil) -> Bool {
		guard let sslCtx = getCtx(forHost: forHost)?.sslCtx else {
			return false
		}
		let r = SSL_CTX_load_verify_locations(sslCtx, caFilePath, caDirPath)
		return r == 1
	}

	public func useCertificateFile(cert: String, forHost: String? = nil) -> Bool {
		guard let sslCtx = getCtx(forHost: forHost)?.sslCtx else {
			return false
		}
		let r = SSL_CTX_use_certificate_file(sslCtx, cert, SSL_FILETYPE_PEM)
		return r == 1
	}

	public func useCertificateChainFile(cert crt: String, forHost: String? = nil) -> Bool {
		guard let sslCtx = getCtx(forHost: forHost)?.sslCtx else {
			return false
		}
		let r = SSL_CTX_use_certificate_chain_file(sslCtx, crt)
		return r == 1
	}

	public func useCertificateChain(cert crt: String, forHost: String? = nil) -> Bool {
		guard let sslCtx = getCtx(forHost: forHost)?.sslCtx else {
			return false
		}
		let bio = BIO_new(BIO_s_mem())
		defer {
			BIO_free(bio)
		}
		BIO_puts(bio, crt)
		let certificate = PEM_read_bio_X509(bio, nil, nil, nil)
		let r = SSL_CTX_use_certificate(sslCtx, certificate)
		return r == 1
	}

	public func usePrivateKeyFile(cert crt: String, forHost: String? = nil) -> Bool {
		guard let sslCtx = getCtx(forHost: forHost)?.sslCtx else {
			return false
		}
		let r = SSL_CTX_use_PrivateKey_file(sslCtx, crt, SSL_FILETYPE_PEM)
		return r == 1
	}

	/// Use a stringified version of the certificate.
	public func usePrivateKey(cert crt: String, forHost: String? = nil) -> Bool {
		guard let sslCtx = getCtx(forHost: forHost)?.sslCtx else {
			return false
		}
		let bio = BIO_new(BIO_s_mem())
		defer {
			BIO_free(bio)
		}
		BIO_puts(bio, crt)
		let pKey = PEM_read_bio_PrivateKey(bio, nil, nil, nil)
		let r = SSL_CTX_use_PrivateKey(sslCtx, pKey)
		return r == 1
	}

	public func checkPrivateKey(forHost: String? = nil) -> Bool {
		guard let sslCtx = getCtx(forHost: forHost)?.sslCtx else {
			return false
		}
		let r = SSL_CTX_check_private_key(sslCtx)
		return r == 1
	}

	public func setClientCA(path: String, verifyMode: OpenSSLVerifyMode, forHost: String? = nil) -> Bool {
		guard let sslCtx = getCtx(forHost: forHost)?.sslCtx else {
			return false
		}
		let oldList = SSL_CTX_get_client_CA_list(sslCtx)
		SSL_CTX_set_client_CA_list(sslCtx, SSL_load_client_CA_file(path))
		let newList = SSL_CTX_get_client_CA_list(sslCtx)

		if let oldNb = oldList,
			let newNb = newList,
			copenssl_stack_st_X509_NAME_num(oldNb)
				+ 1 ==
			copenssl_stack_st_X509_NAME_num(newNb) {

			SSL_CTX_set_verify(sslCtx, verifyMode.rawValue, nil)
			return true
		}
		return false
	}

	public func subscribeCAVerify(verifyMode: OpenSSLVerifyMode, forHost: String? = nil, callback: @escaping VerifyCACallbackFunc) {
		guard let sslCtx = getCtx(forHost: forHost)?.sslCtx else {
			return
		}
		SSL_CTX_set_verify(sslCtx, verifyMode.rawValue, callback)
	}
}

extension NetTCPSSL {
	/// If ALPN is used, this will be the negotiated protocol for this accepted socket.
	/// This will be nil if ALPN is not enabled OR if the client and server share no common protocols.
	public var alpnNegotiated: String? {
		guard let ssl = self.ssl else {
			return nil
		}
		var ptr: UnsafePointer<UInt8>?  = nil
		var len: UInt32 = 0
		SSL_get0_alpn_selected(ssl, &ptr, &len)
		if len > 0, let ptr = ptr {
			var selectedChars = [UInt8]()
			for n in 0..<Int(len) {
				selectedChars.append(ptr[n])
			}
			let negotiated = String(validatingUTF8: selectedChars)
			return negotiated
		}
		return nil
	}
	/// Given a list of protocol names, such as h2, http/1.1, this will enable ALPN protocol selection.
	/// The name of the server+client matched protocol will be available in the `.alpnNegotiated` property.
	/// This protocol list can be set on the server or client socket. Accepted/connected sockets
	/// will have `.alpnNegotiated` set to the negotiated protocol.
	public func enableALPN(protocols: [String], forHost: String? = nil) {
		let buffer: [UInt8] = protocols.map { Array($0.utf8) }
			.map { [UInt8($0.count)] + $0 }
			.reduce([], +)

		enableALPN(buffer: buffer, forHost: forHost)
	}

	func enableALPN(buffer: [UInt8], forHost: String? = nil) {
		guard let ctx = getCtx(forHost: forHost)?.sslCtx, !buffer.isEmpty else {
			return
		}
		if let ptr = copenssl_CRYPTO_malloc(buffer.count, #file, #line) {
			memcpy(ptr, buffer, buffer.count)
			SSL_CTX_set_ex_data(ctx, NetTCPSSL.sslCtxALPNBufferIndex, ptr)
			SSL_CTX_set_ex_data(ctx, NetTCPSSL.sslCtxALPNBufferSizeIndex, UnsafeMutableRawPointer(bitPattern: buffer.count))

			enableALPNServer(forHost: forHost)
			SSL_CTX_set_alpn_protos(ctx, ptr.assumingMemoryBound(to: UInt8.self), UInt32(buffer.count))
		}
	}

	func enableALPNServer(forHost: String? = nil) {
		guard let ctx = getCtx(forHost: forHost)?.sslCtx else {
			return
		}
		typealias alpnSelectCallbackFunc = @convention(c) (UnsafeMutablePointer<SSL>?, UnsafeMutablePointer<UnsafePointer<UInt8>?>?, UnsafeMutablePointer<UInt8>?, UnsafePointer<UInt8>?, UInt32, UnsafeMutableRawPointer?) -> Int32
        // swiftlint:disable line_length
		let callback: alpnSelectCallbackFunc = { (ssl: UnsafeMutablePointer<SSL>?, outBuf: UnsafeMutablePointer<UnsafePointer<UInt8>?>?, outLen: UnsafeMutablePointer<UInt8>?, clientBuf: UnsafePointer<UInt8>?, clientLen: UInt32, _: UnsafeMutableRawPointer?) -> Int32 in

			guard let ctx = SSL_get_SSL_CTX(ssl),
					let ptr = SSL_CTX_get_ex_data(ctx, NetTCPSSL.sslCtxALPNBufferIndex) else {
				return OPENSSL_NPN_NO_OVERLAP
			}
			let ptrLength = Int(bitPattern: SSL_CTX_get_ex_data(ctx, NetTCPSSL.sslCtxALPNBufferSizeIndex))

			let serverBuf = ptr.assumingMemoryBound(to: UInt8.self)
			guard let clientBuf = clientBuf,
				let outBuf = outBuf else {
					return OPENSSL_NPN_NO_OVERLAP
			}
			let serverLen = UInt32(ptrLength)
			return outBuf.withMemoryRebound(to: Optional<UnsafeMutablePointer<UInt8>>.self, capacity: 1) { outBuf in
				let result = SSL_select_next_proto(outBuf, outLen,
				                                   serverBuf, serverLen,
				                                   clientBuf, clientLen)
				if result == OPENSSL_NPN_NEGOTIATED {
					return SSL_TLSEXT_ERR_OK
				}
				return SSL_TLSEXT_ERR_NOACK
			}
		}
		SSL_CTX_set_alpn_select_cb(ctx, callback, nil)
	}
}

extension NetTCPSSL {
	public var serverNameIdentified: String? {
		guard let ssl = self.ssl else {
			return nil
		}
		guard let serverNameRaw = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name),
			let serverName = String(validatingUTF8: serverNameRaw) else {
				return  nil
		}
		return serverName
	}
    // swiftlint:disable type_name
	func enableSNIServer() {
		guard let ctx = self.sslCtx, !sniContextMap.isEmpty else {
			return
		}
		typealias sniCallback = @convention(c) (UnsafeMutablePointer<SSL>?, UnsafeMutablePointer<Int32>?, UnsafeMutableRawPointer?) -> Int32
		typealias ctxCallback = (@convention(c) () -> Swift.Void)
		let callback: sniCallback = { (ssl: UnsafeMutablePointer<SSL>?, _: UnsafeMutablePointer<Int32>?, arg: UnsafeMutableRawPointer?) -> Int32 in

			guard let userDataCheck = arg else {
				return 1
			}
			guard let serverNameRaw = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name),
				let serverName = String(validatingUTF8: serverNameRaw) else {
				return 1
			}
			guard let raw = SSL_get_ex_data(ssl, NetTCPSSL.sslAcceptingNetIndex) else {
				return 1
			}

			let child = Unmanaged<NetTCPSSL>.fromOpaque(raw).takeUnretainedValue()
			let parent = Unmanaged<NetTCPSSL>.fromOpaque(UnsafeMutableRawPointer(userDataCheck)).takeUnretainedValue()
			if let fndCtx = parent.sniContextMap[serverName] {
				SSL_set_SSL_CTX(ssl, fndCtx.sslCtx)
				child.trackCtx = fndCtx
			} else if let fndCtx = parent.sniContextMap["*"] {
				SSL_set_SSL_CTX(ssl, fndCtx.sslCtx)
				child.trackCtx = fndCtx
			}
			return 1
		}

		let opaqueCallback = unsafeBitCast(callback, to: ctxCallback.self)
		SSL_CTX_callback_ctrl(ctx,
		                      SSL_CTRL_SET_TLSEXT_SERVERNAME_CB,
		                      opaqueCallback)
		let opaqueMe = Unmanaged.passUnretained(self).toOpaque()
		SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG, 0, opaqueMe)
	}
}
