//
//  ViewController.swift
//  PerfectServerHTTPApp
//
//  Created by Kyle Jessup on 2015-10-25.
//  Copyright © 2015 PerfectlySoft. All rights reserved.
//

import Cocoa

class ViewController: NSViewController, NSTextFieldDelegate {
	
	@IBOutlet var startStopButton: NSButton?
	@IBOutlet var urlButton: NSButton?
	@IBOutlet var portTextField: NSTextField?
	@IBOutlet var addressTextField: NSTextField?
	@IBOutlet var documentRootTextField: NSTextField?
	
	var serverUrl: String {
		let appDel = AppDelegate.sharedInstance
		let url = "http://\(appDel.serverAddress):\(appDel.serverPort)/"
		return url
	}
	
	override func viewDidLoad() {
		super.viewDidLoad()
	}

	override func viewWillAppear() {
		super.viewWillAppear()
		
		self.portTextField?.stringValue = String(AppDelegate.sharedInstance.serverPort)
		self.addressTextField?.stringValue = String(AppDelegate.sharedInstance.serverAddress)
		self.documentRootTextField?.stringValue = String(AppDelegate.sharedInstance.documentRoot)
	}
	
	override func viewDidAppear() {
		super.viewDidAppear()
		self.updateButtonTitle()
	}
	
	override var representedObject: AnyObject? {
		didSet {
		// Update the view, if already loaded.
		}
	}

	@IBAction
	func toggleServer(sender: AnyObject) {
		let appDel = AppDelegate.sharedInstance
		if appDel.serverIsRunning() {
			appDel.stopServer()
		} else {
			do {
				try appDel.startServer()
			} catch { }
		}
		self.updateButtonTitle()
	}
	
	@IBAction
	func chooseDocumentRoot(sender: NSButton) {
		let panel = NSOpenPanel()
		panel.allowsMultipleSelection = false
		panel.canChooseDirectories = true
		panel.canChooseFiles = false
		
		if panel.runModal() == NSFileHandlingPanelOKButton {
			if let path = panel.URL, pathPath = path.path {
				self.documentRootTextField!.stringValue = pathPath
			}
		}
	}
	
	func updateButtonTitle() {
		dispatch_async(dispatch_get_main_queue()) {
			let appDel = AppDelegate.sharedInstance
			if appDel.serverIsRunning() {
				self.startStopButton?.title = "Stop Server"
			} else {
				self.startStopButton?.title = "Start Server"
			}
			self.urlButton!.title = self.serverUrl
		}
	}
	
	private func rebootServer() {
		let appDel = AppDelegate.sharedInstance
		let time_a = dispatch_time(0, Int64(NSEC_PER_SEC) * Int64(1))
		
		self.updateButtonTitle()
		dispatch_after(time_a, dispatch_get_main_queue()) {
			do {
				try appDel.startServer()
			} catch { }
			dispatch_after(dispatch_time(0, Int64(NSEC_PER_SEC) * Int64(2)), dispatch_get_main_queue()) {
				self.updateButtonTitle()
			}
		}
	}
	
	func control(control: NSControl, textShouldEndEditing fieldEditor: NSText) -> Bool {
		let appDel = AppDelegate.sharedInstance
		let wasRunning = appDel.serverIsRunning()
		if wasRunning {
			appDel.stopServer()
		}
		if control == self.portTextField! {
			appDel.serverPort = UInt16(control.stringValue) ?? 8181
		} else if control == self.addressTextField! {
			appDel.serverAddress = control.stringValue
		} else if control == self.documentRootTextField! {
			appDel.documentRoot = control.stringValue
		}
		self.urlButton!.title = self.serverUrl
		if wasRunning {
			self.rebootServer()
		}
		return true
	}
	
	@IBAction
	func openUrl(sender: NSButton) {
		let url = self.serverUrl
		NSWorkspace.sharedWorkspace().openURL(NSURL(string: url)!)
	}
}

