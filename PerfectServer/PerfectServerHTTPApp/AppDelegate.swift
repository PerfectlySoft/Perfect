//
//  AppDelegate.swift
//  PerfectServerHTTPApp
//
//  Created by Kyle Jessup on 2015-10-25.
//  Copyright © 2015 PerfectlySoft. All rights reserved.
//

import Cocoa
import PerfectLib

@NSApplicationMain
class AppDelegate: NSObject, NSApplicationDelegate {

	static var sharedInstance: AppDelegate {
		return NSApplication.sharedApplication().delegate as! AppDelegate
	}
	
	var httpServer: HTTPServer?
	let serverDispatchQueue = dispatch_queue_create("HTTP Server Accept", DISPATCH_QUEUE_SERIAL)
	
	var serverPort: UInt16 = 8181
	var serverAddress: String = "0.0.0.0"
	var documentRoot: String = "./webroot/"
	
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
		let tcp = NetTCP()
		defer {
			tcp.close()
		}
		
		do {
			try tcp.bind(serverPort, address: serverAddress)
			return false
		} catch {
			
		}
		return true
	}
	
	func startServer() throws {
		try self.startServer(serverPort, address: serverAddress, documentRoot: documentRoot)
	}
	
	func startServer(port: UInt16, address: String, documentRoot: String) throws {
		dispatch_async(self.serverDispatchQueue) {
			do {
				try Dir(documentRoot).create()
				self.httpServer = HTTPServer(documentRoot: documentRoot)
				try self.httpServer!.start(port, bindAddress: address)
			} catch {
				print("Exiting server run loop")
			}
		}
	}

	func stopServer() {
		self.httpServer!.stop()
	}
}

