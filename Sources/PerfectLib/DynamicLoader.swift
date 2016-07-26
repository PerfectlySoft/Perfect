//
//  DynamicLoader.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/13/15.
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

import Foundation
#if os(Linux)

#else
	import Darwin
#endif

struct DynamicLoader {

	// sketchy! PerfectServerModuleInit is not defined as convention(c)
	// but it does not seem to matter provided it is Void->Void
	// I am unsure on how to convert a void* to a legit Swift ()->() func
	typealias InitFunction = @convention(c) ()->()

	let initFuncName = "PerfectServerModuleInit"

	init() {

	}

	func loadFramework(atPath at: String) -> Bool {
		let resolvedPath = URL(fileURLWithPath: at).resolvingSymlinksInPath()
		let moduleName = resolvedPath.deletingPathExtension().lastPathComponent
		let file = File(resolvedPath.path + "/" + moduleName)
        guard file.exists else {
            return false
        }
        let realPath = file.realPath
        return self.loadRealPath(realPath, moduleName: moduleName)
	}

	func loadLibrary(atPath at: String) -> Bool {
		var moduleName = URL(fileURLWithPath: at).deletingPathExtension().lastPathComponent
		if moduleName.begins(with: "lib") {
			moduleName.characters.removeFirst(3)
		}
		return self.loadRealPath(at, moduleName: moduleName)
	}

	private func loadRealPath(_ realPath: String, moduleName: String) -> Bool {
		guard let openRes = dlopen(realPath, RTLD_NOW|RTLD_LOCAL) else {
			Log.warning(message: "Errno \(String(validatingUTF8: dlerror())!)")
			return false
		}

        // this is fragile
		let newModuleName = moduleName.stringByReplacing(string: "-", withString: "_").stringByReplacing(string: " ", withString: "_")
		let symbolName = "_TF\(newModuleName.utf8.count)\(newModuleName)\(initFuncName.utf8.count)\(initFuncName)FT_T_"
		let sym = dlsym(openRes, symbolName)
        guard sym != nil else {
            Log.warning(message: "Error loading \(realPath). Symbol \(symbolName) not found.")
            dlclose(openRes)
            return false
        }
        let f: InitFunction = unsafeBitCast(sym, to: InitFunction.self)
        f()
        return true
	}
}
