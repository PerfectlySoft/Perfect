//
//  Routing.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2015-12-11.
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

public typealias RequestHandlerGenerator = PageHandlerRegistry.RequestHandlerGenerator

/// Holds the registered routes.
public struct RouteMap: CustomStringConvertible {
	
	/// Pretty prints all route information.
	public var description: String {
		var s = self.root.description
		for (method, root) in self.methodRoots {
			s.appendContentsOf("\n" + method + ":\n" + root.description)
		}
		return s
	}
	
	private var root = RouteNode() // root node for any request method
	private var methodRoots = [String:RouteNode]() // by convention, use all upper cased method names for inserts/lookups
	
	/// Lookup a route based on the URL path.
	/// Returns the handler generator if found.
	subscript(path: String, webResponse: WebResponse) -> RequestHandlerGenerator? {
		get {
			let components = path.lowercaseString.pathComponents
			var g = components.generate()
			let _ = g.next() // "/"
			
			let method = webResponse.request.requestMethod().uppercaseString
			if let root = self.methodRoots[method] {
				if let handler = root.findHandler("", generator: g, webResponse: webResponse) {
					return handler
				}
			}
			return self.root.findHandler("", generator: g, webResponse: webResponse)
		}
	}
	
	/// Add a route to the system.
	/// `Routing.Routes["/foo/*/baz"] = { _ in return ExampleHandler() }`
	public subscript(path: String) -> RequestHandlerGenerator? {
		get {
			return nil // Swift does not currently allow set-only subscripts
		}
		set {
			self.root.addPathSegments(path.lowercaseString.pathComponents.generate(), h: newValue!)
		}
	}
	
	/// Add an array of routes for a given handler.
	/// `Routing.Routes[ ["/", "index.html"] ] = { _ in return ExampleHandler() }`
	public subscript(paths: [String]) -> RequestHandlerGenerator? {
		get {
			return nil
		}
		set {
			for path in paths {
				self[path] = newValue
			}
		}
	}
	
	/// Add a route to the system using the indicated HTTP request method.
	/// `Routing.Routes["GET", "/foo/*/baz"] = { _ in return ExampleHandler() }`
	public subscript(method: String, path: String) -> RequestHandlerGenerator? {
		get {
			return nil // Swift does not currently allow set-only subscripts
		}
		set {
			let uppered = method.uppercaseString
			if let root = self.methodRoots[uppered] {
				root.addPathSegments(path.lowercaseString.pathComponents.generate(), h: newValue!)
			} else {
				let root = RouteNode()
				self.methodRoots[uppered] = root
				root.addPathSegments(path.lowercaseString.pathComponents.generate(), h: newValue!)
			}
		}
	}
	
	/// Add an array of routes for a given handler using the indicated HTTP request method.
	/// `Routing.Routes["GET", ["/", "index.html"] ] = { _ in return ExampleHandler() }`
	public subscript(method: String, paths: [String]) -> RequestHandlerGenerator? {
		get {
			return nil // Swift does not currently allow set-only subscripts
		}
		set {
			for path in paths {
				self[method, path] = newValue
			}
		}
	}
}

/// This wraps up the routing related functionality.
/// Enable the routing system by calling:
/// ```
/// Routing.Handler.registerGlobally()
/// ```
/// This should be done in your `PerfectServerModuleInit` function.
/// The system supports HTTP method based routing, wildcards and variables.
///
/// Add routes in the following manner:
/// ```
/// 	Routing.Routes["GET", ["/", "index.html"] ] = { (_:WebResponse) in return IndexHandler() }
/// 	Routing.Routes["/foo/*/baz"] = { _ in return EchoHandler() }
/// 	Routing.Routes["/foo/bar/baz"] = { _ in return EchoHandler() }
/// 	Routing.Routes["GET", "/user/{id}/baz"] = { _ in return Echo2Handler() }
/// 	Routing.Routes["POST", "/user/{id}/baz"] = { _ in return Echo3Handler() }
/// ```
/// The closure you provide should return an instance of `PageHandler`. It is provided the WebResponse object to permit further customization.
/// Variables set by the routing process can be accessed through the `WebRequest.urlVariables` dictionary.
/// Note that a PageHandler *MUST* call `WebResponse.requestCompletedCallback()` when the request has completed.
/// This does not need to be done within the `handleRequest` method.
public class Routing {
	
	/// The routes which have been configured.
	static public var Routes = RouteMap()
	
	private init() {}
	
	/// This is the main handler for the logic of the URL routing system.
	/// If must be enabled by calling `Routing.Handler.registerGlobally`
	public class Handler: RequestHandler {
		
		/// Install the URL routing system.
		/// This is required if this system is to be utilized, otherwise it will not be available.
		static public func registerGlobally() {
			PageHandlerRegistry.addRequestHandler { (_:WebResponse) -> RequestHandler in
				return Routing.Handler()
			}
		}
		
		/// Handle the request, triggering the routing system.
		/// If a route is discovered the request is sent to the new handler.
		public func handleRequest(request: WebRequest, response: WebResponse) {
			let pathInfo = request.requestURI().characters.split("?").map { String($0) }.first ?? "/"
			
			if let handler = Routing.Routes[pathInfo, response] {
				handler(response).handleRequest(request, response: response)
			} else {
				response.setStatus(404, message: "NOT FOUND")
				response.appendBodyString("The file \(pathInfo) was not found.")
				response.requestCompletedCallback()
			}
		}
		
	}
	
}

class RouteNode: CustomStringConvertible {
	
	typealias ComponentGenerator = IndexingGenerator<[String]>
	
	var description: String {
		return self.descriptionTabbed(0)
	}
	
	private func putTabs(count: Int) -> String {
		var s = ""
		for _ in 0..<count {
			s.appendContentsOf("\t")
		}
		return s
	}
	
	func descriptionTabbedInner(tabCount: Int) -> String {
		var s = ""
		for (_, node) in self.subNodes {
			s.appendContentsOf("\(self.putTabs(tabCount))\(node.descriptionTabbed(tabCount+1))")
		}
		for node in self.variables {
			s.appendContentsOf("\(self.putTabs(tabCount))\(node.descriptionTabbed(tabCount+1))")
		}
		if let node = self.wildCard {
			s.appendContentsOf("\(self.putTabs(tabCount))\(node.descriptionTabbed(tabCount+1))")
		}
		return s
	}
	
	func descriptionTabbed(tabCount: Int) -> String {
		var s = ""
		if let _ = self.handlerGenerator {
			s.appendContentsOf("/+h\n")
		}
		s.appendContentsOf(self.descriptionTabbedInner(tabCount))
		return s
	}
	
	var handlerGenerator: RequestHandlerGenerator?
	var wildCard: RouteNode?
	var variables = [RouteNode]()
	var subNodes = [String:RouteNode]()
	
	func findHandler(currentComponent: String, generator: ComponentGenerator, webResponse: WebResponse) -> RequestHandlerGenerator? {
		var m = generator
		if let p = m.next() where p != "/" {
			
			// variables
			for node in self.variables {
				if let h = node.findHandler(p, generator: m, webResponse: webResponse) {
					return self.successfulRoute(currentComponent, handler: node.successfulRoute(p, handler: h, webResponse: webResponse), webResponse: webResponse)
				}
			}
			
			// paths
			if let node = self.subNodes[p] {
				if let h = node.findHandler(p, generator: m, webResponse: webResponse) {
					return self.successfulRoute(currentComponent, handler: node.successfulRoute(p, handler: h, webResponse: webResponse), webResponse: webResponse)
				}
			}
			
			// wildcards
			if let node = self.wildCard {
				if let h = node.findHandler(p, generator: m, webResponse: webResponse) {
					return self.successfulRoute(currentComponent, handler: node.successfulRoute(p, handler: h, webResponse: webResponse), webResponse: webResponse)
				}
			}
			
		} else if self.handlerGenerator != nil {
			
			return self.handlerGenerator
			
		} else {
			// wildcards
			if let node = self.wildCard {
				if let h = node.findHandler("", generator: m, webResponse: webResponse) {
					return self.successfulRoute(currentComponent, handler: node.successfulRoute("", handler: h, webResponse: webResponse), webResponse: webResponse)
				}
			}
		}
		return nil
	}
	
	func successfulRoute(currentComponent: String, handler: RequestHandlerGenerator, webResponse: WebResponse) -> RequestHandlerGenerator {
		return handler
	}
	
	func addPathSegments(g: ComponentGenerator, h: RequestHandlerGenerator) {
		var m = g
		if let p = m.next() {
			if p == "/" {
				self.addPathSegments(m, h: h)
			} else {
				self.addPathSegment(p, g: m, h: h)
			}
		} else {
			self.handlerGenerator = h
		}
	}
	
	private func addPathSegment(component: String, g: ComponentGenerator, h: RequestHandlerGenerator) {
		if let node = self.nodeForComponent(component) {
			node.addPathSegments(g, h: h)
		}
	}
	
	private func nodeForComponent(component: String) -> RouteNode? {
		guard !component.isEmpty else {
			return nil
		}
		if component == "*" {
			if self.wildCard == nil {
				self.wildCard = RouteWildCard()
			}
			return self.wildCard
		}
		if component.characters.count >= 3 && component[component.startIndex] == "{" && component[component.endIndex.predecessor()] == "}" {
			let node = RouteVariable(name: component.substringWith(Range(start: component.startIndex.successor(), end: component.endIndex.predecessor())))
			self.variables.append(node)
			return node
		}
		if let node = self.subNodes[component] {
			return node
		}
		let node = RoutePath(name: component)
		self.subNodes[component] = node
		return node
	}
	
}

class RoutePath: RouteNode {
	
	override func descriptionTabbed(tabCount: Int) -> String {
		var s = "/\(self.name)"
		
		if let _ = self.handlerGenerator {
			s.appendContentsOf("+h\n")
		} else {
			s.appendContentsOf("\n")
		}
		s.appendContentsOf(self.descriptionTabbedInner(tabCount))
		return s
	}
	
	var name = ""
	init(name: String) {
		self.name = name
	}
	
	// RoutePaths don't need to perform any special checking.
	// Their path is validated by the fact that they exist in their parent's `subNodes` dict.
}

class RouteWildCard: RouteNode {
	
	override func descriptionTabbed(tabCount: Int) -> String {
		var s = "/*"
		
		if let _ = self.handlerGenerator {
			s.appendContentsOf("+h\n")
		} else {
			s.appendContentsOf("\n")
		}
		s.appendContentsOf(self.descriptionTabbedInner(tabCount))
		return s
	}
	
}

class RouteVariable: RouteNode {
	
	override func descriptionTabbed(tabCount: Int) -> String {
		var s = "/{\(self.name)}"
		
		if let _ = self.handlerGenerator {
			s.appendContentsOf("+h\n")
		} else {
			s.appendContentsOf("\n")
		}
		s.appendContentsOf(self.descriptionTabbedInner(tabCount))
		return s
	}
	
	var name = ""
	init(name: String) {
		self.name = name
	}
	
	override func successfulRoute(currentComponent: String, handler: RequestHandlerGenerator, webResponse: WebResponse) -> RequestHandlerGenerator {
        if let decodedComponent = currentComponent.stringByDecodingURL {
            webResponse.request.urlVariables[self.name] = decodedComponent
        } else {
            webResponse.request.urlVariables[self.name] = currentComponent
        }
		return handler
	}
	
}







