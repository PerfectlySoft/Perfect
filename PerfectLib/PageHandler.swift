//
//  PageHandler.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/8/15.
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

/// Use this class to register handlers which supply values for mustache templates.
/// This registration would occur in the `PerfectServerModuleInit` function which every PerfectServer library module should define. PerfectServer will call this method when it loads each module as the server process starts up.
///
/// Example:
///```
///	public func PerfectServerModuleInit() {
///		PageHandlerRegistry.addPageHandler("test_page_handler") {
///			(r: WebResponse) -> PageHandler in
///			return MyTestHandler()
///		}
///	}
///```
///
/// In the example above, the class MyTestHandler is registering to be the handler for mustache templates which include a handler
/// pragma with the `test_page_handler` identifier.
///
/// The following example shows what such a mustache template file might look like:
///```
///    {{% handler:test_page_handler }}
///    Top of the page test {{key1}}
///    {{key2}}
///    That's all
///```
public class PageHandlerRegistry {
	
	private static var generator = [String: PageHandlerGenerator]()
	
	private static var globalRequestHandler: RequestHandlerGenerator?
	
	/// A function which returns a new PageHandler object given a WebRequest
	public typealias PageHandlerGenerator = WebResponse -> PageHandler
	
	public typealias RequestHandlerGenerator = WebResponse -> RequestHandler
	
	/// Registers a new handler for the given name
	/// - parameter named: The name for the handler. This name should be used in a mustache `handler` pragma tag in order to associate the template with its handler.
	/// - parameter generator: The generator function which will be called to produce a new handler object.
	public static func addPageHandler(named: String, generator: PageHandlerGenerator) {
		PageHandlerRegistry.generator[named] = generator
	}
	
	public static func addRequestHandler(generator: RequestHandlerGenerator) {
		PageHandlerRegistry.globalRequestHandler = generator
	}
	
	/// Registers a new handler for the given name
	/// - parameter named: The name for the handler. This name should be used in a mustache `handler` pragma tag in order to associate the template with its handler.
	/// - parameter generator: The generator function which will be called to produce a new handler object.
	public static func addPageHandler(named: String, generator: () -> PageHandler) {
		addPageHandler(named) {
			(_:WebResponse) -> PageHandler in
			return generator()
		}
	}
	
	static func getPageHandler(named: String, forResponse: WebResponse) -> PageHandler? {
		let h = PageHandlerRegistry.generator[named]
		if let fnd = h {
			return fnd(forResponse)
		}
		return nil
	}
	
	static func hasGlobalHandler() -> Bool {
		return PageHandlerRegistry.globalRequestHandler != nil
	}
	
	static func getRequestHandler(forResponse: WebResponse) -> RequestHandler? {
		if let fnd = PageHandlerRegistry.globalRequestHandler {
			return fnd(forResponse)
		}
		return nil
	}
}

/// Classes which intend to supply values for mustache templates should impliment this protocol.
public protocol PageHandler {
	/// This function is called by the system in order for the handler to generate the values which will be used to complete the mustache template.
	/// It returns a dictionary of values.
	/// - parameter context: The MustacheEvaluationContext object for the current template.
	/// - parameter collector: The MustacheEvaluationOutputCollector for the current template.
	/// - returns: The dictionary of values which will be used when populating the mustache template.
	func valuesForResponse(context: MustacheEvaluationContext, collector: MustacheEvaluationOutputCollector) throws -> MustacheEvaluationContext.MapType
	
}

public protocol RequestHandler {
	func handleRequest(request: WebRequest, response: WebResponse)
}


