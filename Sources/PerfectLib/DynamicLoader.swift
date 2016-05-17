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

#if os(Linux)
	import SwiftGlibc
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
		let resolvedPath = at.stringByResolvingSymlinksInPath
		let moduleName = resolvedPath.lastPathComponent.stringByDeletingPathExtension
		let file = File(resolvedPath + "/" + moduleName)
		if file.exists() {
			let realPath = file.realPath()
			return self.loadRealPath(realPath, moduleName: moduleName)
		}
		return false
	}
	
	func loadLibrary(atPath at: String) -> Bool {
		var fileName = at.lastPathComponent
		if fileName.begins(with: "lib") {
		#if swift(>=3.0)
			fileName.characters.removeFirst(3)
		#else
			fileName.removeRange(fileName.startIndex..<fileName.startIndex.advancedBy(3))
		#endif
		}
		let moduleName = fileName.stringByDeletingPathExtension
		return self.loadRealPath(at, moduleName: moduleName)
	}
	
	private func loadRealPath(_ realPath: String, moduleName: String) -> Bool {
		let openRes = dlopen(realPath, RTLD_NOW|RTLD_LOCAL)
		if openRes != nil {
			// this is fragile
			let newModuleName = moduleName.stringByReplacing(string: "-", withString: "_").stringByReplacing(string: " ", withString: "_")
			let symbolName = "_TF\(newModuleName.utf8.count)\(newModuleName)\(initFuncName.utf8.count)\(initFuncName)FT_T_"
			let sym = dlsym(openRes, symbolName)
			if sym != nil {
				let f: InitFunction = unsafeBitCast(sym, to: InitFunction.self)
				f()
				return true
			} else {
				print("Error loading \(realPath). Symbol \(symbolName) not found.")
				dlclose(openRes)
			}
		} else {
			print("Errno \(String(validatingUTF8: dlerror())!)")
		}
		return false
	}
	
}







