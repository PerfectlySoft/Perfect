//
//  ViewController.swift
//  Tap Tracker
//
//  Created by Kyle Jessup on 2015-10-22.
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


import UIKit
import MapKit
import PerfectLib

// adjust these to match whatever the server is listening on
// these are the default values which should work unless the server has been changed
let END_POINT_HOST = "localhost"
let END_POINT_PORT = 8181

let END_POINT = "http://\(END_POINT_HOST):\(END_POINT_PORT)/TapTracker"

class ViewController: UIViewController, CLLocationManagerDelegate {

	var selectedLocation: CLLocation? = nil
	let locationManager: CLLocationManager
	
	var timeStr = ""
	var lat = 0.0, long = 0.0
	
	override init(nibName nibNameOrNil: String?, bundle nibBundleOrNil: NSBundle?) {
		self.locationManager = CLLocationManager()
		super.init(nibName: nibNameOrNil, bundle: nibBundleOrNil)
	}
	
	required init?(coder aDecoder: NSCoder) {
		self.locationManager = CLLocationManager()
		super.init(coder: aDecoder)
	}
	
	override func viewDidLoad() {
		super.viewDidLoad()
		self.title = "Tap Tracker"
		self.locationManager.delegate = self
		if self.locationManager.respondsToSelector("requestWhenInUseAuthorization") {
			self.locationManager.requestWhenInUseAuthorization()
		}
		self.locationManager.startUpdatingLocation()
	}

	override func didReceiveMemoryWarning() {
		super.didReceiveMemoryWarning()
	}

	func locationManager(manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
		if let loc = locations.first {
			self.selectedLocation = loc
		}
	}
	
	@IBAction
	func buttonPressed(Sender: AnyObject) {
		if let loc = self.selectedLocation {
			
			let lat = loc.coordinate.latitude
			let long = loc.coordinate.longitude
			
			let postBody = "lat=\(lat)&long=\(long)"
			
			let req = NSMutableURLRequest(URL: NSURL(string: END_POINT)!)
			req.HTTPMethod = "POST"
			req.HTTPBody = postBody.dataUsingEncoding(NSUTF8StringEncoding)
			
			let session = NSURLSession.sharedSession()
			
			let task = session.dataTaskWithRequest(req, completionHandler: {
				(d:NSData?, res:NSURLResponse?, e:NSError?) -> Void in
				if let _ = e {
					print("Request failed with error \(e!)")
				} else {
					
					let strData =  String(data: d!, encoding: NSUTF8StringEncoding)
					print("Request succeeded with data \(strData)")
					do {
						if let strOk = strData {
							let jsonDecoded = try JSONDecode().decode(strOk)
							if let jsonMap = jsonDecoded as? JSONDictionaryType {
								
								if let sets = jsonMap.dictionary["resultSets"] as? JSONArrayType {
									// just one result in this app
									if let result = sets.array.first as? JSONDictionaryType {
										if let timeStr = result.dictionary["time"] as? String,
											let lat = result.dictionary["lat"] as? Double,
											let long = result.dictionary["long"] as? Double {
											
												self.timeStr = timeStr
												self.lat = lat
												self.long = long
												
												dispatch_async(dispatch_get_main_queue()) {
													self.performSegueWithIdentifier("showMap", sender: self)
												}
										}
									}
								}
							}
						}
					} catch let ex {
						print("JSON decoding failed with exception \(ex)")
					}
				}
			})
			
			task.resume()
			
		} else {
			// no location
			
			let alert = UIAlertController(title: "No Location", message: "Ensure that location services are available and try again.", preferredStyle: .Alert)
			let action = UIAlertAction(title: "OK", style: .Default) {
				(a:UIAlertAction) -> Void in
			}
			alert.addAction(action)
			self.presentViewController(alert, animated: true) { }
		}
	}
	
	override func prepareForSegue(segue: UIStoryboardSegue, sender: AnyObject?) {
		if let dest = segue.destinationViewController as? MapViewController {
			dest.timeStr = self.timeStr
			dest.lat = self.lat
			dest.long = self.long
		}
	}

}

