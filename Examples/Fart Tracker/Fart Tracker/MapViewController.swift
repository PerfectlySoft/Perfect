//
//  MapViewController.swift
//  Fart Tracker
//
//  Created by Kyle Jessup on 2015-10-27.
//
//

import UIKit
import MapKit

class MapViewController: UIViewController {

	var timeStr = ""
	var lat = 0.0, long = 0.0
	
	@IBOutlet var mapView: MKMapView?
	
	@objc
	class FartLocationViewAnnotation: NSObject, MKAnnotation {
		var coordinate = CLLocationCoordinate2D()
		var title: String? = ""
		var subtitle: String? = ""
		
		init(coordinate: CLLocationCoordinate2D, title: String?, subtitle: String?) {
			self.coordinate = coordinate
			self.title = title
			self.subtitle = subtitle
		}
	}
	
    override func viewDidLoad() {
        super.viewDidLoad()

        // Do any additional setup after loading the view.
    }

	override func viewWillAppear(animated: Bool) {
		super.viewWillAppear(animated)
		
		let coord = CLLocationCoordinate2D(latitude: lat, longitude: long)
		let annotation = FartLocationViewAnnotation(coordinate: coord, title: "Last Fart", subtitle: self.timeStr)
		self.mapView?.addAnnotation(annotation)
		let span = MKCoordinateSpanMake(0.1, 0.1)
		self.mapView?.region = MKCoordinateRegionMake(coord, span)
	}
	
    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }
}
