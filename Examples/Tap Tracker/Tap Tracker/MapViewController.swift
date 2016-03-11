//
//  MapViewController.swift
//  Tap Tracker
//
//  Created by Kyle Jessup on 2015-10-27.
//	Copyright (C) 2015 PerfectlySoft, Inc.
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
