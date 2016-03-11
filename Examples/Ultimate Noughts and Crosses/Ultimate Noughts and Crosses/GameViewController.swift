//
//  GameViewController.swift
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

let CONTENT_TAG = 10

struct GridLocation {
	var contentView: UIView
	var major: (x: Int, y: Int)
	var minor: (x: Int, y: Int)
}

extension UIView {
	
	@IBInspectable
	var cornerRadius: CGFloat {
		get {
			return layer.cornerRadius
		}
		set {
			layer.cornerRadius = newValue
			layer.masksToBounds = newValue > 0
		}
	}
	
	var viewCenter: CGPoint {
		let r = self.bounds
		return CGPoint(x: CGRectGetMidX(r), y: CGRectGetMidY(r))
	}
	
	var contentView: UIView? {
		for child in self.subviews {
			if child.tag == CONTENT_TAG {
				return child
			}
		}
		return nil
	}
	
	func childWithTag(tag: Int) -> UIView? {
		for child in self.subviews {
			if child.tag == tag {
				return child
			}
		}
		return nil
	}
	
	var gridLocation: GridLocation? {
		if self.tag == CONTENT_TAG {
			if let superView = self.superview {
				if let loc1 = superView.locationForTag {
					if let superView2 = superView.superview {
						if let superViewWrap = superView2.superview {
							if superViewWrap.tag == CONTENT_TAG {
								if let superView3 = superViewWrap.superview {
									if let loc2 = superView3.locationForTag {
										return GridLocation(contentView: self, major: loc2, minor: loc1)
									}
								}
							}
						}
					}
				}
			}
		}
		return nil
	}
	
	var locationForTag: (Int, Int)? {
		switch self.tag {
		case 1:
			return (0, 0)
		case 2:
			return (1, 0)
		case 3:
			return (2, 0)
		case 4:
			return (0, 1)
		case 5:
			return (1, 1)
		case 6:
			return (2, 1)
		case 7:
			return (0, 2)
		case 8:
			return (1, 2)
		case 9:
			return (2, 2)
		default:
			return nil
		}
	}
}

class GameViewController: UIViewController {

	@IBOutlet var mainBoard: UIView?
	var localPlayerNick = ""
	
    override func viewDidLoad() {
        super.viewDidLoad()
		self.loadBoard()
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }
	
	func loadBoard() {
		let mainInner = loadOneBoard()
		self.placeInsideAndConstrain(mainInner, superView: mainBoard!)
		
		var children = [Int:UIView]()
		for child in mainInner.subviews {
			let tag = child.tag
			
			if tag != 0 {
				children[tag] = child
			}
		}
		
		for tag in 1...9 {
			if let view = children[tag] {
				let newChild = self.loadOneBoard()
				if let subHolder = view.contentView {
					self.placeInsideAndConstrain(newChild, superView: subHolder)
				}
			}
		}
	}
	
	func loadOneBoard() -> UIView {
		let loaded = NSBundle.mainBundle().loadNibNamed("Board", owner: self, options: nil)
		let v = loaded[0] as! UIView
		return v
	}
	
	func placeInsideAndConstrain(childView: UIView, superView: UIView) {
		childView.translatesAutoresizingMaskIntoConstraints = false
		superView.addSubview(childView)
		
		superView.addConstraints([
			NSLayoutConstraint(item: childView, attribute: NSLayoutAttribute.Top, relatedBy: NSLayoutRelation.Equal, toItem: superView, attribute: NSLayoutAttribute.Top, multiplier: 1.0, constant: 0.0),
			NSLayoutConstraint(item: childView, attribute: NSLayoutAttribute.Leading, relatedBy: NSLayoutRelation.Equal, toItem: superView, attribute: NSLayoutAttribute.Leading, multiplier: 1.0, constant: 0.0),
			NSLayoutConstraint(item: childView, attribute: NSLayoutAttribute.Bottom, relatedBy: NSLayoutRelation.Equal, toItem: superView, attribute: NSLayoutAttribute.Bottom, multiplier: 1.0, constant: 0.0),
			NSLayoutConstraint(item: childView, attribute: NSLayoutAttribute.Trailing, relatedBy: NSLayoutRelation.Equal, toItem: superView, attribute: NSLayoutAttribute.Trailing, multiplier: 1.0, constant: 0.0)
			])
	}
	
	override func touchesBegan(touches: Set<UITouch>, withEvent event: UIEvent?) {
		if let first = touches.first {
			let pt = first.locationInView(mainBoard!)
			if let hit = mainBoard!.hitTest(pt, withEvent: event) {
				if let gridLocation = hit.gridLocation {
					
					print("Major: \(gridLocation.major) Minor: \(gridLocation.minor)")
					
					// !FIX! check if it's a valid location
					let ex = rand() % 2 == 0
					let img = UIImageView(image: UIImage(named: ex ? "Ex" : "Oh"))
					gridLocation.contentView.addSubview(img)
					img.frame = gridLocation.contentView.bounds
					img.center = gridLocation.contentView.viewCenter
				}
			}
			
		}
	}
	
    /*
    // MARK: - Navigation

    // In a storyboard-based application, you will often want to do a little preparation before navigation
    override func prepareForSegue(segue: UIStoryboardSegue, sender: AnyObject?) {
        // Get the new view controller using segue.destinationViewController.
        // Pass the selected object to the new view controller.
    }
    */

}
