//
//  ViewController.swift
//  PerfectServerHTTPApp
//
//  Created by Kyle Jessup on 2015-10-25.
//	Copyright (C) 2015 PerfectlySoft, Inc.
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


import Cocoa

class ViewController: NSViewController, NSTextFieldDelegate {
	
	@IBOutlet var startStopButton: NSButton?
	@IBOutlet var urlButton: NSButton?
	@IBOutlet var chooseButton: NSButton?
	
	@IBOutlet var portTextField: NSTextField?
	@IBOutlet var addressTextField: NSTextField?
	@IBOutlet var documentRootTextField: NSTextField?
	
	@IBOutlet var startStopButtonBackground: NSView?
	@IBOutlet var urlButtonBackground: NSView?
	@IBOutlet var chooseButtonBackground: NSView?
	
	var savedFont: NSFont?
	
	var serverUrl: String {
		let appDel = AppDelegate.sharedInstance
		let url = "http://\(appDel.serverAddress):\(appDel.serverPort)/"
		return url
	}
	
	override func viewDidLoad() {
		super.viewDidLoad()
		
		self.view.wantsLayer = true
		
		self.startStopButtonBackground?.layer?.backgroundColor = NSColor(red:0.93, green:0.32, blue:0.2, alpha:1).CGColor
		self.urlButtonBackground?.layer?.backgroundColor = NSColor(red:0.22, green:0.22, blue:0.22, alpha:1).CGColor
        
        self.startStopButtonBackground?.layer?.cornerRadius = 3
        self.urlButtonBackground?.layer?.cornerRadius = 3
		
		self.savedFont = self.startStopButton?.cell?.font
		
		self.setBlackTextButton(self.startStopButton!, title: self.startStopButton!.title)
		self.setBlackTextButton(self.urlButton!, title: self.urlButton!.title)
		self.setBlackTextButton(self.chooseButton!, title: self.chooseButton!.title)
	}

	func setBlackTextButton(button: NSButton, title: String) {
		let attrTitle = NSMutableAttributedString(string: title, attributes: [NSForegroundColorAttributeName: NSColor.blackColor(), NSFontAttributeName: self.savedFont!])
		button.attributedTitle = attrTitle
	}
    
    func setWhiteTextButton(button: NSButton, title: String) {
        let attrTitle = NSMutableAttributedString(string: title, attributes: [NSForegroundColorAttributeName: NSColor.whiteColor(), NSFontAttributeName: self.savedFont!])
        button.attributedTitle = attrTitle
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
				self.setWhiteTextButton(self.startStopButton!, title: "Stop Server")
                self.startStopButtonBackground?.layer?.backgroundColor = NSColor(red:0.93, green:0.32, blue:0.2, alpha:1).CGColor
			} else {
				self.setWhiteTextButton(self.startStopButton!, title: "Start Server")
                self.startStopButtonBackground?.layer?.backgroundColor = NSColor(red:0.12, green:0.81, blue:0.43, alpha:1).CGColor
			}
			self.setWhiteTextButton(self.urlButton!, title: self.serverUrl)
		}
	}
	
	private func rebootServer() {
		let appDel = AppDelegate.sharedInstance
		let time_a = dispatch_time(0, Int64(NSEC_PER_SEC) * Int64(1))
		
		self.updateButtonTitle()
		dispatch_after(time_a, dispatch_get_main_queue()) { [weak self] in
			do {
				try appDel.startServer()
			} catch { }
			dispatch_after(dispatch_time(0, Int64(NSEC_PER_SEC) * Int64(2)), dispatch_get_main_queue()) {
				self?.updateButtonTitle()
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
		self.setBlackTextButton(self.urlButton!, title: self.serverUrl)
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

