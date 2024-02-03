//
//  Routing.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2015-12-11.
//  Copyright © 2015 PerfectlySoft. All rights reserved.
//
// ===----------------------------------------------------------------------===//
//
// This source file is part of the Perfect.org open source project
//
// Copyright (c) 2015 - 2016 PerfectlySoft Inc. and the Perfect project authors
// Licensed under Apache License v2.0
//
// See http://perfect.org/licensing.html for license information
//
// ===----------------------------------------------------------------------===//
//

import PerfectLib

/// Function which receives request and response objects and generates content.
public typealias RequestHandler = (HTTPRequest, HTTPResponse) -> ()

/// Object which maps uris to handler.
/// RouteNavigators are given to the HTTPServer to control its content generation.
public protocol RouteNavigator: CustomStringConvertible {
	/// Given an array of URI path components and HTTPRequest, return the handler or nil if there was none.
	func findHandlers(pathComponents components: [String], webRequest: HTTPRequest) -> [RequestHandler]?
}

public extension RouteNavigator {
	func findHandler(pathComponents: [String], webRequest: HTTPRequest) -> RequestHandler? {
		return findHandlers(pathComponents: pathComponents, webRequest: webRequest)?.last
	}
}

public extension RouteNavigator {
	/// Given a URI and HTTPRequest, return the handler or nil if there was none.
	func findHandler(uri: String, webRequest: HTTPRequest) -> RequestHandler? {
		return findHandler(pathComponents: uri.routePathComponents, webRequest: webRequest)
	}
	/// Given a URI and HTTPRequest, return the handler or nil if there was none.
	func findHandlers(uri: String, webRequest: HTTPRequest) -> [RequestHandler]? {
		return findHandlers(pathComponents: uri.routePathComponents, webRequest: webRequest)
	}
}

// The url variable key under which the remaining path in a trailing wild card will be placed.
public let routeTrailingWildcardKey = "_trailing_wildcard_"

/// Combines a method, uri and handler
public struct Route {
	public let methods: [HTTPMethod]
	public let uri: String
	public let handler: RequestHandler
	/// A single method, a uri and handler.
	public init(method: HTTPMethod, uri: String, handler: @escaping RequestHandler) {
		self.methods = [method]
		self.uri = uri
		self.handler = handler
	}
	/// An array of methods, a uri and handler.
	public init(methods: [HTTPMethod], uri: String, handler: @escaping RequestHandler) {
		self.methods = methods
		self.uri = uri
		self.handler = handler
	}
	/// A uri and a handler on any method.
	public init(uri: String, handler: @escaping RequestHandler) {
		self.methods = HTTPMethod.allMethods
		self.uri = uri
		self.handler = handler
	}
}

/// A group of routes. Add one or more routes to this object then call its navigator property to get the RouteNavigator.
/// Can be created with a baseUri. All routes which are added will have their URIs prefixed with this value.
public struct Routes {
	var routes = [Route]()
	var moreRoutes = [Routes]()
	let baseUri: String
	let handler: RequestHandler?

	/// Initialize with no baseUri.
	public init(handler: RequestHandler? = nil) {
		self.baseUri = ""
		self.handler = handler
	}

	/// Initialize with a baseUri.
	public init(baseUri: String, handler: RequestHandler? = nil) {
		self.baseUri = Routes.sanitizeBaseUri(baseUri)
		self.handler = handler
	}

	/// Initialize with a array of Route.
	public init(_ routes: [Route]) {
		self.baseUri = ""
		self.handler = nil
		add(routes)
	}

	/// Initialize with a baseUri and array of Route.
	public init(baseUri: String, routes: [Route]) {
		self.baseUri = Routes.sanitizeBaseUri(baseUri)
		self.handler = nil
		add(routes)
	}

	/// Add all the routes in the Routes object to this one.
	public mutating func add(_ routes: Routes) {
		moreRoutes.append(routes)
	}

	/// Add all the routes in the Routes array to this one.
	public mutating func add(_ routes: [Route]) {
		for route in routes {
			add(route)
		}
	}

	/// Add one Route to this object.
	public mutating func add(_ route: Route, routes vroots: Route...) {
		routes.append(route)
		vroots.forEach { add($0) }
	}

	/// Add the given method, uri and handler as a route.
	public mutating func add(method: HTTPMethod, uri: String, handler: @escaping RequestHandler) {
		add(Route(method: method, uri: uri, handler: handler))
	}

	/// Add the given method, uris and handler as a route.
	public mutating func add(method: HTTPMethod, uris: [String], handler: @escaping RequestHandler) {
		uris.forEach {
			add(method: method, uri: $0, handler: handler)
		}
	}

	/// Add the given uri and handler as a route.
	/// This will add the route for all standard methods.
	public mutating func add(uri: String, handler: @escaping RequestHandler) {
		add(Route(uri: uri, handler: handler))
	}

	/// Add the given method, uris and handler as a route.
	/// This will add the route for all standard methods.
	public mutating func add(uris: [String], handler: @escaping RequestHandler) {
		for uri in uris {
			add(uri: uri, handler: handler)
		}
	}

	static func sanitizeBaseUri(_ uri: String) -> String {
		let split = uri.split(separator: "/").map(String.init)
		let ret = "/" + split.joined(separator: "/")
		return ret
	}

	static func sanitizeFragmentUri(_ uri: String) -> String {
		let endSlash = uri.hasSuffix("/")
		let split = uri.split(separator: "/").map(String.init)
		let ret = "/" + split.joined(separator: "/") + (endSlash ? "/" : "")
		return ret
	}

	struct Navigator: RouteNavigator {
		let map: [HTTPMethod: RouteNode]

		var description: String {
			var s = ""
			for (method, root) in self.map {
				s.append("\n\(method):\n\(root.description)")
			}
			return s
		}

		func findHandlers(pathComponents components: [String], webRequest: HTTPRequest) -> [RequestHandler]? {
			let method = webRequest.method
			guard !components.isEmpty, let root = self.map[method] else {
				return nil
			}
			var g = components.makeIterator()
			if components[0] == "/" {
				_ = g.next()
			}
			guard let handlers = root.findHandler(currentComponent: "", generator: g, webRequest: webRequest) else {
				return nil
			}
			return handlers.compactMap { $0 }
		}
	}

	private func formatException(route r: String, error: Error) -> String {
		return "\(error) - \(r)"
	}
}

extension Routes {
	/// Return the RouteNavigator for this object.
	public var navigator: RouteNavigator {
		guard let map = try? nodeMap() else {
			return Navigator(map: [:])
		}
		return Navigator(map: map)
	}

	func nodeMap() throws -> [HTTPMethod: RouteNode] {
		var working = [HTTPMethod: RouteNode]()
		let paths = self.paths(baseUri: "")

		for (method, uris) in paths {
			let root = RouteNode()
			working[method] = root
			for path in uris {
				let uri = Routes.sanitizeFragmentUri(path.path)
				let handler = path.handler
				let terminal = path.terminal
				var gen = uri.routePathComponents.makeIterator()
				if uri.hasPrefix("/") {
					_ = gen.next()
				}
				let node = try root.getNode(gen)
				node.terminal = terminal
				node.handler = handler
			}
		}

		return working
	}

	struct PathHandler {
		let path: String
		let handler: RequestHandler
		let terminal: Bool
	}

	func paths(baseUri: String = "") -> [HTTPMethod: [PathHandler]] {
		var paths = [HTTPMethod: [PathHandler]]()
		let newBaseUri = baseUri + self.baseUri
		moreRoutes.forEach {
			let newp = $0.paths(baseUri: newBaseUri)
			paths = merge(newp, into: paths)
		}
		routes.forEach { route in
			let uri = newBaseUri + "/" + route.uri
			var newpaths = [HTTPMethod: [PathHandler]]()
			route.methods.forEach { method in
				newpaths[method] = [PathHandler(path: uri, handler: route.handler, terminal: true)]
			}
			paths = merge(newpaths, into: paths)
		}
		if let handler = self.handler {
			for (key, value) in paths {
				paths[key] = value + [PathHandler(path: newBaseUri, handler: handler, terminal: false)]
			}
		}
		return paths
	}

	func merge(_ dict: [HTTPMethod: [PathHandler]], into: [HTTPMethod: [PathHandler]]) -> [HTTPMethod: [PathHandler]] {
		var ret = into
		for (key, value) in dict {
			if var fnd = ret[key] {
				fnd.append(contentsOf: value)
				ret[key] = fnd
			} else {
				ret[key] = value
			}
		}
		return ret
	}
}

extension Routes {
	// Add all the routes in the Routes object to this one.
	@available(*, deprecated, message: "Use Routes.add(_:Routes)")
	public mutating func add(routes: Routes) {
		for route in routes.routes {
			self.add(route)
		}
	}
}

extension String {
	var routePathComponents: [String] {
		return self.filePathComponents
	}
}

private enum RouteException: Error {
	case invalidRoute
}

private enum RouteItemType {
	case wildcard, trailingWildcard, variable(String), path, trailingSlash
	init(_ comp: String) {
		if comp == "*" {
			self = .wildcard
		} else if comp == "**" {
			self = .trailingWildcard
		} else if comp == "/" {
			self = .trailingSlash
		} else if comp.count >= 3 && comp[comp.startIndex] == "{" && comp[comp.index(before: comp.endIndex)] == "}" {
			self = .variable(String(comp[comp.index(after: comp.startIndex)..<comp.index(before: comp.endIndex)]))
		} else {
			self = .path
		}
	}
}

class RouteNode {

	typealias ComponentGenerator = IndexingIterator<[String]>

	var handler: RequestHandler?
	var trailingWildCard: RouteNode?
	var wildCard: RouteNode?
	var variables = [RouteNode]()
	var subNodes = [String: RouteNode]()
	var terminal = true // an end point. not an intermediary

	func descriptionTabbed(_ tabCount: Int) -> String {
		var s = ""
		if nil != self.handler {
			s.append("/+h\n")
		}
		s.append(self.descriptionTabbedInner(tabCount))
		return s
	}

	func appendToHandlers(_ handlers: [RequestHandler?]) -> [RequestHandler?] {
		// terminal handlers are not included in chaining
		if terminal {
			return handlers
		}
		return [handler] + handlers
	}

	func findHandler(currentComponent curComp: String, generator: ComponentGenerator, webRequest: HTTPRequest) -> [RequestHandler?]? {
		var m = generator
		if let p = m.next() {
			// variables
			for node in self.variables {
				if let h = node.findHandler(currentComponent: p, generator: m, webRequest: webRequest) {
					return appendToHandlers(h)
				}
			}

			// paths
			if let node = self.subNodes[p.lowercased()] {
				if let h = node.findHandler(currentComponent: p, generator: m, webRequest: webRequest) {
					return appendToHandlers(h)
				}
			}

			// wildcard
			if let node = self.wildCard {
				if let h = node.findHandler(currentComponent: p, generator: m, webRequest: webRequest) {
					return appendToHandlers(h)
				}
			}

			// trailing wildcard
			if let node = self.trailingWildCard {
				if let h = node.findHandler(currentComponent: p, generator: m, webRequest: webRequest) {
					return appendToHandlers(h)
				}
			}

		} else if let handler = self.handler {
			if terminal {
				return [handler]
			}
			return nil
		} else {
			// wildcards
			if let node = self.wildCard {
				if let h = node.findHandler(currentComponent: "", generator: m, webRequest: webRequest) {
					return appendToHandlers(h)
				}
			}

			// trailing wildcard
			if let node = self.trailingWildCard {
				if let h = node.findHandler(currentComponent: "", generator: m, webRequest: webRequest) {
					return appendToHandlers(h)
				}
			}
		}
		return nil
	}

	func getNode(_ ing: ComponentGenerator) throws -> RouteNode {
		var g = ing
		if let comp = g.next() {
			let routeType = RouteItemType(comp)
			let node: RouteNode
			switch routeType {
			case .wildcard:
				if wildCard == nil {
					wildCard = RouteWildCard()
				}
				node = wildCard!
			case .trailingWildcard:
				guard nil == g.next() else {
					throw RouteException.invalidRoute
				}
				if trailingWildCard == nil {
					trailingWildCard = RouteTrailingWildCard()
				}
				node = trailingWildCard!
			case .trailingSlash:
				guard nil == g.next() else {
					throw RouteException.invalidRoute
				}
				node = RouteTrailingSlash()
				subNodes[comp] = node
			case .path:
				let compLower = comp.lowercased()
				if let existing = subNodes[compLower] {
					node = existing
				} else {
					node = RoutePath(name: compLower)
					subNodes[compLower] = node
				}
			case .variable(let name):
				let dups = variables.compactMap { $0 as? RouteVariable }.filter { $0.name == name }
				if dups.isEmpty {
					let varble = RouteVariable(name: name)
					variables.append(varble)
					node = varble
				} else {
					node = dups[0]
				}
			}
			return try node.getNode(g)
		} else {
			return self
		}
	}
}

extension RouteNode: CustomStringConvertible {
	var description: String {
		return self.descriptionTabbed(0)
	}

	private func putTabs(_ count: Int) -> String {
		var s = ""
		for _ in 0..<count {
			s.append("\t")
		}
		return s
	}

	func descriptionTabbedInner(_ tabCount: Int) -> String {
		var s = ""
		for (_, node) in self.subNodes {
			s.append("\(self.putTabs(tabCount))\(node.descriptionTabbed(tabCount+1))")
		}
		for node in self.variables {
			s.append("\(self.putTabs(tabCount))\(node.descriptionTabbed(tabCount+1))")
		}
		if let node = self.wildCard {
			s.append("\(self.putTabs(tabCount))\(node.descriptionTabbed(tabCount+1))")
		}
		if let node = self.trailingWildCard {
			s.append("\(self.putTabs(tabCount))\(node.descriptionTabbed(tabCount+1))")
		}
		return s
	}
}

class RoutePath: RouteNode {

	let name: String
	init(name: String) {
		self.name = name
	}

	override func descriptionTabbed(_ tabCount: Int) -> String {
		var s = "/\(self.name)"

		if nil != self.handler {
			s.append("+h\n")
		} else {
			s.append("\n")
		}
		s.append(self.descriptionTabbedInner(tabCount))
		return s
	}

	// RoutePaths don't need to perform any special checking.
	// Their path is validated by the fact that they exist in their parent's `subNodes` dict.
}

class RouteWildCard: RouteNode {

	override func descriptionTabbed(_ tabCount: Int) -> String {
		var s = "/*"
		if nil != self.handler {
			s.append("+h\n")
		} else {
			s.append("\n")
		}
		s.append(self.descriptionTabbedInner(tabCount))
		return s
	}
}

class RouteTrailingWildCard: RouteWildCard {

	override func descriptionTabbed(_ tabCount: Int) -> String {
		var s = "/**"
		if nil != self.handler {
			s.append("+h\n")
		} else {
			s.append("\n")
		}
		s.append(self.descriptionTabbedInner(tabCount))
		return s
	}

	override func findHandler(currentComponent curComp: String, generator: ComponentGenerator, webRequest: HTTPRequest) -> [RequestHandler?]? {
		let trailingVar = "/\(curComp)" + generator.map { "/" + $0 }.joined(separator: "")
		webRequest.urlVariables[routeTrailingWildcardKey] = trailingVar
		if let handler = self.handler {
			return [handler]
		}
		return nil
	}
}

class RouteTrailingSlash: RouteNode {

	override func descriptionTabbed(_ tabCount: Int) -> String {
		var s = "/"
		if nil != self.handler {
			s.append("+h\n")
		} else {
			s.append("\n")
		}
		s.append(self.descriptionTabbedInner(tabCount))
		return s
	}

	override func findHandler(currentComponent curComp: String, generator: ComponentGenerator, webRequest: HTTPRequest) -> [RequestHandler?]? {
		var m = generator
		guard curComp == "/", nil == m.next(), let handler = self.handler else {
			return nil
		}
		return [handler]
	}
}

class RouteVariable: RouteNode {

	let name: String
	init(name: String) {
		self.name = name
	}

	override func descriptionTabbed(_ tabCount: Int) -> String {
		var s = "/{\(self.name)}"
		if nil != self.handler {
			s.append("+h\n")
		} else {
			s.append("\n")
		}
		s.append(self.descriptionTabbedInner(tabCount))
		return s
	}

	override func findHandler(currentComponent curComp: String, generator: ComponentGenerator, webRequest: HTTPRequest) -> [RequestHandler?]? {
		if let h = super.findHandler(currentComponent: curComp, generator: generator, webRequest: webRequest) {
			if let decodedComponent = curComp.stringByDecodingURL {
				webRequest.urlVariables[self.name] = decodedComponent
			} else {
				webRequest.urlVariables[self.name] = curComp
			}
			return h
		}
		return nil
	}
}

// -- old --
// ALL code below this is obsolete but remains to provide compatability 1.0 based solutions.
// For 1.0 compatability only.
public var compatRoutes: Routes?

// Holds the registered routes.
@available(*, deprecated, message: "Use new Routes API instead")
public struct RouteMap: CustomStringConvertible {

	public typealias RequestHandler = (HTTPRequest, HTTPResponse) -> ()

	public var description: String {
		return compatRoutes?.navigator.description ?? "no routes"
	}

	public subscript(path: String) -> RequestHandler? {
		get {
			return nil // Swift does not currently allow set-only subscripts
		}
		set {
			guard let handler = newValue else {
				return
			}
			if nil == compatRoutes {
				compatRoutes = Routes()
			}
			compatRoutes?.add(method: .get, uri: path, handler: handler)
		}
	}

	public subscript(paths: [String]) -> RequestHandler? {
		get {
			return nil
		}
		set {
			for path in paths {
				self[path] = newValue
			}
		}
	}

	public subscript(method: HTTPMethod, path: String) -> RequestHandler? {
		get {
			return nil // Swift does not currently allow set-only subscripts
		}
		set {
			guard let handler = newValue else {
				return
			}
			if nil == compatRoutes {
				compatRoutes = Routes()
			}
			compatRoutes?.add(method: method, uri: path, handler: handler)
		}
	}

	public subscript(method: HTTPMethod, paths: [String]) -> RequestHandler? {
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

@available(*, deprecated, message: "Use new Routes API instead")
public struct Routing {
	static public var Routes = RouteMap()
	private init() {}
}
