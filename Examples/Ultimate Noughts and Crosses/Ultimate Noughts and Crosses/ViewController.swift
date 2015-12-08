//
//  ViewController.swift
//  Ultimate Noughts and Crosses
//
//  Created by Kyle Jessup on 2015-10-28.
//  Copyright © 2015 PerfectlySoft. All rights reserved.
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

