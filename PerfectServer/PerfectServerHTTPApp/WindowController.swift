//
//  WindowController.swift
//  PerfectServer
//
//  Created by Sofiane Beors on 06/12/2015.
//  Copyright © 2015 PerfectlySoft. All rights reserved.
//

import Cocoa

class WindowController: NSWindowController {

    override func windowDidLoad() {
        super.windowDidLoad()
        
        self.window?.titleVisibility = .Hidden
        self.window?.titlebarAppearsTransparent = true
        self.window?.movableByWindowBackground  = true
    }
}
