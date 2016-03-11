//
//  ViewController.swift
//  Ultimate Noughts and Crosses
//
//  Created by Kyle Jessup on 2015-10-28.
//  Copyright © 2015 PerfectlySoft. All rights reserved.
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

import UIKit
import PerfectLib

class ViewController: UIViewController {

	var nick = ""
	
	override func viewDidLoad() {
		super.viewDidLoad()
		// Do any additional setup after loading the view, typically from a nib.
	}

	override func didReceiveMemoryWarning() {
		super.didReceiveMemoryWarning()
		// Dispose of any resources that can be recreated.
	}

	override func shouldPerformSegueWithIdentifier(identifier: String, sender: AnyObject?) -> Bool {
		if identifier == "newGame" {
			dispatch_async(dispatch_get_main_queue()) {
				
				let alert = UIAlertController(title: "Choose Nick", message: "Choose a nickname for yourself in this game.", preferredStyle: .Alert)
				
				let cancel = UIAlertAction(title: "Cancel", style: .Cancel) { (_) in }
				let letsPlay = UIAlertAction(title: "Let's Play", style: .Default) {
					(a:UIAlertAction) -> Void in
					
					let nickField = alert.textFields![0]
					
					self.startGame(nickField.text!)
				}
				
				alert.addTextFieldWithConfigurationHandler {
					(textField) in
					textField.placeholder = "Nick Name"
					
					let defs = NSUserDefaults.standardUserDefaults()
					if let existingNick = defs.stringForKey("defaultNick") {
						textField.text = existingNick
					}
				}
				alert.addAction(letsPlay)
				alert.addAction(cancel)
				
				self.presentViewController(alert, animated: true) { }
			}
			return false
		}
		return true
	}
	
	func startGame(nick: String) {
		let defs = NSUserDefaults.standardUserDefaults()
		defs.setValue(nick, forKey: "defaultNick")
		defs.synchronize()
		self.nick = nick
		self.performSegueWithIdentifier("newGame", sender: nil)
	}
	
	override func prepareForSegue(segue: UIStoryboardSegue, sender: AnyObject?) {
		if let dest = segue.destinationViewController as? GameViewController {
			dest.localPlayerNick = self.nick
		}
	}
}

