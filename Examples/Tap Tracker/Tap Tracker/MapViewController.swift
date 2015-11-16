//
//  MapViewController.swift
//  Tap Tracker
//
//  Created by Kyle Jessup on 2015-10-27.
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

class MapViewController: UIViewController {

	// These are set before the segue to this view
	var timeStr = ""
	var lat = 0.0, long = 0.0
	
	@IBOutlet var mapView: MKMapView?
	
	@objc
	class TapLocationViewAnnotation: NSObject, MKAnnotation {
		var coordinate = CLLocationCoordinate2D()
		var title: String? = ""
		var subtitle: String? = ""
		
		init(coordinate: CLLocationCoordinate2D, title: String?, subtitle: String?) {
			self.coordinate = coordinate
			self.title = title
			self.subtitle = subtitle
		}
	}

	override func viewWillAppear(animated: Bool) {
		super.viewWillAppear(animated)
		
		let coord = CLLocationCoordinate2D(latitude: lat, longitude: long)
		let annotation = TapLocationViewAnnotation(coordinate: coord, title: "Last Tap", subtitle: self.timeStr)
		self.mapView?.addAnnotation(annotation)
		let span = MKCoordinateSpanMake(0.1, 0.1)
		self.mapView?.region = MKCoordinateRegionMake(coord, span)
	}
}
