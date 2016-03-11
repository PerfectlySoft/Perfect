//
//  URLSessionDelegate.swift
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

import Foundation

class URLSessionDelegate: NSObject, NSURLSessionDataDelegate {
	
	let username: String
	let password: String
	let completionHandler:(d:NSData?, res:NSURLResponse?, e:NSError?)->()
	var data: NSData?
	var response: NSURLResponse?
	var suppliedCreds = false
	
	init(username: String, password: String, completionHandler: (d:NSData?, res:NSURLResponse?, e:NSError?)->()) {
		self.username = username
		self.password = password
		self.completionHandler = completionHandler
	}
	
	func URLSession(session: NSURLSession, task: NSURLSessionTask, didReceiveChallenge challenge: NSURLAuthenticationChallenge, completionHandler: (NSURLSessionAuthChallengeDisposition, NSURLCredential?) -> Void) {
		if self.suppliedCreds {
			completionHandler(.PerformDefaultHandling, nil)
		} else {
			self.suppliedCreds = true
			let cred = NSURLCredential(user: username, password: password, persistence: .ForSession)
			completionHandler(.UseCredential, cred)
		}
	}

	func URLSession(session: NSURLSession, dataTask: NSURLSessionDataTask, didReceiveData data: NSData) {
		self.data = data
	}
	
	func URLSession(session: NSURLSession, dataTask: NSURLSessionDataTask, didReceiveResponse response: NSURLResponse, completionHandler: (NSURLSessionResponseDisposition) -> Void) {
		self.response = response
		completionHandler(NSURLSessionResponseDisposition.Allow)
	}
	
	func URLSession(session: NSURLSession, task: NSURLSessionTask, didCompleteWithError error: NSError?) {
		self.completionHandler(d: self.data, res: self.response, e: error)
	}
}
