//
//  LoginViewController.swift
//  Authenticator
//
//  Created by Kyle Jessup on 2015-11-12.
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

let LOGIN_SEGUE_ID = "loginSegue"

class LoginViewController: UIViewController, NSURLSessionDelegate, UITextFieldDelegate {

	@IBOutlet var emailAddressText: UITextField?
	@IBOutlet var passwordText: UITextField?
	
	var message = ""
	
    override func viewDidLoad() {
        super.viewDidLoad()

        // Do any additional setup after loading the view.
        self.emailAddressText?.delegate = self
        self.passwordText?.delegate = self
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }

	override func shouldPerformSegueWithIdentifier(identifier: String, sender: AnyObject?) -> Bool {
		if identifier == LOGIN_SEGUE_ID {
			// start login process
			tryLogin()
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

	func tryLogin() {
		
		let urlSessionDelegate = URLSessionDelegate(username: self.emailAddressText!.text!, password: self.passwordText!.text!) {
			(d:NSData?, res:NSURLResponse?, e:NSError?) -> Void in
			
			if let _ = e {
				
				self.message = "Failed with error \(e!)"
				
			} else if let httpRes = res as? NSHTTPURLResponse where httpRes.statusCode != 200 {
				
				self.message = "Failed with HTTP code \(httpRes.statusCode)"
				
			} else {
				
				let deserialized = try! NSJSONSerialization.JSONObjectWithData(d!, options: NSJSONReadingOptions.AllowFragments)
				self.message = "Logged in \(deserialized["firstName"]!!) \(deserialized["lastName"]!!)"
			}
			dispatch_async(dispatch_get_main_queue()) {
				self.performSegueWithIdentifier(LOGIN_SEGUE_ID, sender: nil)
			}
		}
		
		let sessionConfig = NSURLSession.sharedSession().configuration
		let session = NSURLSession(configuration: sessionConfig, delegate: urlSessionDelegate, delegateQueue: nil)
		let req = NSMutableURLRequest(URL: NSURL(string: END_POINT + "login")!)
		req.addValue("application/json", forHTTPHeaderField: "Accept")
		
		let task = session.dataTaskWithRequest(req)
		
		task.resume()
	}

    func textFieldShouldReturn(textField: UITextField) -> Bool {
        textField.resignFirstResponder()
        return true
    }
}
