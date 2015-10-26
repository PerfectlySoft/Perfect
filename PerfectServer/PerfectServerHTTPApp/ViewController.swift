//
//  ViewController.swift
//  PerfectServerHTTPApp
//
//  Created by Kyle Jessup on 2015-10-25.
//  Copyright © 2015 PerfectlySoft. All rights reserved.
//

import Cocoa

class ViewController: NSViewController {

	@IBOutlet
	var startStopButton: NSButton?
	
	override func viewDidLoad() {
		super.viewDidLoad()

		// Do any additional setup after loading the view.
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
			} catch {
			}
		}
		self.updateButtonTitle()
	}
	
	func updateButtonTitle() {
		dispatch_async(dispatch_get_main_queue()) {
			let appDel = AppDelegate.sharedInstance
			if appDel.serverIsRunning() {
				self.startStopButton?.title = "Stop Server"
			} else {
				self.startStopButton?.title = "Start Server"
			}
		}
	}
	
}

