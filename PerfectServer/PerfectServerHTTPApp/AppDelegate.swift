//
//  AppDelegate.swift
//  PerfectServerHTTPApp
//
//  Created by Kyle Jessup on 2015-10-25.
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


import Cocoa
import PerfectLib

let KEY_SERVER_PORT = "server.port"
let KEY_SERVER_ADDRESS = "server.address"
let KEY_SERVER_ROOT = "server.root"

@NSApplicationMain
class AppDelegate: NSObject, NSApplicationDelegate {

	static var sharedInstance: AppDelegate {
		return NSApplication.sharedApplication().delegate as! AppDelegate
	}
	
	var httpServer: HTTPServer?
	let serverDispatchQueue = dispatch_queue_create("HTTP Server Accept", DISPATCH_QUEUE_SERIAL)
	
	var serverPort: UInt16 = 8181 {
		didSet {
			NSUserDefaults.standardUserDefaults().setValue(Int(self.serverPort), forKey: KEY_SERVER_PORT)
			NSUserDefaults.standardUserDefaults().synchronize()
		}
	}
	var serverAddress: String = "0.0.0.0" {
		didSet {
			NSUserDefaults.standardUserDefaults().setValue(self.serverAddress, forKey: KEY_SERVER_ADDRESS)
			NSUserDefaults.standardUserDefaults().synchronize()
		}
	}
	var documentRoot: String = "./webroot/" {
		didSet {
			NSUserDefaults.standardUserDefaults().setValue(self.documentRoot, forKey: KEY_SERVER_ROOT)
			NSUserDefaults.standardUserDefaults().synchronize()
		}
	}
	
	override init() {
		let r = UInt16(NSUserDefaults.standardUserDefaults().integerForKey(KEY_SERVER_PORT))
		if r == 0 {
			self.serverPort = 8181
		} else {
			self.serverPort = r
		}
		self.serverAddress = NSUserDefaults.standardUserDefaults().stringForKey(KEY_SERVER_ADDRESS) ?? "0.0.0.0"
		self.documentRoot = NSUserDefaults.standardUserDefaults().stringForKey(KEY_SERVER_ROOT) ?? "./webroot/"
	}
	
	func applicationDidFinishLaunching(aNotification: NSNotification) {
		
		let ls = PerfectServer.staticPerfectServer
		ls.initializeServices()
		
		do {
			try self.startServer()
		} catch {
			
		}
	}

	func applicationWillTerminate(aNotification: NSNotification) {
		// Insert code here to tear down your application
	}
	
	@IBAction
	func startServer(sender: AnyObject) {
		do { try self.startServer() } catch {}
	}
	
	@IBAction
	func stopServer(sender: AnyObject) {
		self.stopServer()
	}
	
	func serverIsRunning() -> Bool {
		guard let s = self.httpServer else {
			return false
		}
		let tcp = NetTCP()
		defer {
			tcp.close()
		}
		
		do {
			try tcp.bind(s.serverPort, address: s.serverAddress)
			return false
		} catch {
			
		}
		return true
	}
	
	func startServer() throws {
		try self.startServer(serverPort, address: serverAddress, documentRoot: documentRoot)
	}
	
	func startServer(port: UInt16, address: String, documentRoot: String) throws {
		guard nil == self.httpServer else {
			print("Server already running")
			return
		}
		dispatch_async(self.serverDispatchQueue) { [unowned self] in
			do {
				try Dir(documentRoot).create()
				self.httpServer = HTTPServer(documentRoot: documentRoot)
				try self.httpServer!.start(port, bindAddress: address)
			} catch let e {
				print("Exception in server run loop \(e) \(address):\(port)")
			}
			print("Exiting server run loop")
		}
	}

	func stopServer() {
		if let _ = self.httpServer {
			self.httpServer!.stop()
			self.httpServer = nil
		}
	}
}

