//
//  RegisterViewController.swift
//  Authenticator
//
//  Created by Kyle Jessup on 2015-11-12.
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

let REGISTER_SEGUE_ID = "registerSegue"

extension String {
	var forUrl: String {
		return self.stringByAddingPercentEncodingWithAllowedCharacters(NSCharacterSet.URLQueryAllowedCharacterSet())!
	}
}

class RegisterViewController: UIViewController, UITextFieldDelegate {

	@IBOutlet var firstNameText: UITextField?
	@IBOutlet var lastNameText: UITextField?
	@IBOutlet var emailAddressText: UITextField?
	@IBOutlet var password1Text: UITextField?
	@IBOutlet var password2Text: UITextField?
	
	var message = ""
	
    override func viewDidLoad() {
        super.viewDidLoad()

        // Do any additional setup after loading the view.
        self.firstNameText?.delegate = self
        self.lastNameText?.delegate = self
        self.emailAddressText?.delegate = self
        self.password1Text?.delegate = self
        self.password2Text?.delegate = self
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }
	
	override func shouldPerformSegueWithIdentifier(identifier: String, sender: AnyObject?) -> Bool {
		if identifier == REGISTER_SEGUE_ID {
			// start login process
			tryRegister()
			return false
		}
		return true
	}
	
    // In a storyboard-based application, you will often want to do a little preparation before navigation
	override func prepareForSegue(segue: UIStoryboardSegue, sender: AnyObject?) {
		if let dest = segue.destinationViewController as? ResultViewController {
			dest.message = self.message
		}
	}
	
	func tryRegister() {
		
		let session = NSURLSession.sharedSession()
		let postBody = "fname=\(self.firstNameText!.text!.forUrl)&lname=\(self.lastNameText!.text!.forUrl)&email=\(self.emailAddressText!.text!.forUrl)&password=\(self.password1Text!.text!.forUrl)&password2=\(self.password2Text!.text!.forUrl)"
		let req = NSMutableURLRequest(URL: NSURL(string: END_POINT + "register")!)
		
		req.addValue("application/json", forHTTPHeaderField: "Accept")
		req.HTTPMethod = "POST"
		req.HTTPBody = postBody.dataUsingEncoding(NSUTF8StringEncoding)
		
		let task = session.dataTaskWithRequest(req, completionHandler: {
			(d:NSData?, res:NSURLResponse?, e:NSError?) -> Void in
			if let _ = e {
				
				self.message = "Failed with error \(e!)"
				
			} else {
				
				let deserialized = try! NSJSONSerialization.JSONObjectWithData(d!, options: NSJSONReadingOptions.AllowFragments)
				print("\(deserialized)")
				self.message = "Registered \(deserialized["firstName"]!!) \(deserialized["lastName"]!!)"
			}
			dispatch_async(dispatch_get_main_queue()) {
				self.performSegueWithIdentifier(REGISTER_SEGUE_ID, sender: nil)
			}
		})
		
		task.resume()
	}

    func textFieldShouldReturn(textField: UITextField) -> Bool {
        textField.resignFirstResponder()
        return true
    }
}
