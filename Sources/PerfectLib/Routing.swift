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


/// Holds the registered routes.
public struct RouteMap: CustomStringConvertible {
	
	public typealias RequestHandler = (WebRequest, WebResponse) -> Response
	
	/// Pretty prints all route information.
	public var description: String {
		var s = self.root.description
		for (method, root) in self.methodRoots {
			s.append("\n" + method + ":\n" + root.description)
		}
		return s
	}
	
	private let root = RouteNode() // root node for any request method
	private var methodRoots = [String:RouteNode]() // by convention, use all upper cased method names for inserts/lookups
	
	// Lookup a route based on the URL path.
	// Returns the handler generator if found.
	subscript(path: String, webResponse: WebResponse) -> RequestHandler? {
		get {
			let components = path.lowercased().pathComponents
			var g = components.makeIterator()
			let _ = g.next() // "/"
			
			let method = webResponse.request.requestMethod!.uppercased()
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
	public subscript(path: String) -> RequestHandler? {
		get {
			return nil // Swift does not currently allow set-only subscripts
		}
		set {
			self.root.addPathSegments(path.lowercased().pathComponents.makeIterator(), h: newValue!)
		}
	}
	
	/// Add an array of routes for a given handler.
	/// `Routing.Routes[ ["/", "index.html"] ] = { _ in return ExampleHandler() }`
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
	
	/// Add a route to the system using the indicated HTTP request method.
	/// `Routing.Routes["GET", "/foo/*/baz"] = { _ in return ExampleHandler() }`
	public subscript(method: String, path: String) -> RequestHandler? {
		get {
			return nil // Swift does not currently allow set-only subscripts
		}
		set {
			let uppered = method.uppercased()
			if let root = self.methodRoots[uppered] {
				root.addPathSegments(path.lowercased().pathComponents.makeIterator(), h: newValue!)
			} else {
				let root = RouteNode()
				self.methodRoots[uppered] = root
				root.addPathSegments(path.lowercased().pathComponents.makeIterator(), h: newValue!)
			}
		}
	}
	
	/// Add an array of routes for a given handler using the indicated HTTP request method.
	/// `Routing.Routes["GET", ["/", "index.html"] ] = { _ in return ExampleHandler() }`
	public subscript(method: String, paths: [String]) -> RequestHandler? {
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
/// Note that a PageHandler *MUST* call `WebResponse.requestCompleted()` when the request has completed.
/// This does not need to be done within the `handleRequest` method.
public class Routing {
	
	/// The routes which have been configured.
	static public var Routes = RouteMap()
	
	private init() {}
	
	/// Handle the request, triggering the routing system.
	/// If a route is discovered the request is sent to the new handler.
	public static func handleRequest(request: WebRequest, response: WebResponse) -> Response {
		let pathInfo = request.requestURI?.characters.split(separator: "?").map { String($0) }.first ?? "/"
		
		if let handler = Routing.Routes[pathInfo, response] {
			return handler(request, response)
		} else {
            return .NotFound("The file \(pathInfo) was not found.")
		}
	}
	
}

class RouteNode: CustomStringConvertible {
	
	#if swift(>=3.0)
	typealias ComponentGenerator = IndexingIterator<[String]>
	#else
	typealias ComponentGenerator = IndexingGenerator<[String]>
	#endif
	
	var description: String {
		return self.descriptionTabbed(0)
	}
	
	private func putTabs(count: Int) -> String {
		var s = ""
		for _ in 0..<count {
			s.append("\t")
		}
		return s
	}
	
	func descriptionTabbedInner(tabCount: Int) -> String {
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
		return s
	}
	
	func descriptionTabbed(tabCount: Int) -> String {
		var s = ""
		if let _ = self.handler {
			s.append("/+h\n")
		}
		s.append(self.descriptionTabbedInner(tabCount))
		return s
	}
	
	var handler: RouteMap.RequestHandler?
	var wildCard: RouteNode?
	var variables = [RouteNode]()
	var subNodes = [String:RouteNode]()
	
	func findHandler(currentComponent: String, generator: ComponentGenerator, webResponse: WebResponse) -> RouteMap.RequestHandler? {
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
			
		} else if self.handler != nil {
			
			return self.handler
			
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
	
	func successfulRoute(currentComponent: String, handler: RouteMap.RequestHandler, webResponse: WebResponse) -> RouteMap.RequestHandler {
		return handler
	}
	
	func addPathSegments(g: ComponentGenerator, h: RouteMap.RequestHandler) {
		var m = g
		if let p = m.next() {
			if p == "/" {
				self.addPathSegments(m, h: h)
			} else {
				self.addPathSegment(p, g: m, h: h)
			}
		} else {
			self.handler = h
		}
	}
	
	private func addPathSegment(component: String, g: ComponentGenerator, h: RouteMap.RequestHandler) {
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
			let node = RouteVariable(name: component.substringWith(component.startIndex.successor()..<component.endIndex.predecessor()))
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
	
	let name: String
	init(name: String) {
		self.name = name
	}
	
	override func descriptionTabbed(tabCount: Int) -> String {
		var s = "/\(self.name)"
		
		if let _ = self.handler {
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
	
	override func descriptionTabbed(tabCount: Int) -> String {
		var s = "/*"
		
		if let _ = self.handler {
			s.append("+h\n")
		} else {
			s.append("\n")
		}
		s.append(self.descriptionTabbedInner(tabCount))
		return s
	}
	
}

class RouteVariable: RouteNode {
	
	let name: String
	init(name: String) {
		self.name = name
	}
	
	override func descriptionTabbed(tabCount: Int) -> String {
		var s = "/{\(self.name)}"
		
		if let _ = self.handler {
			s.append("+h\n")
		} else {
			s.append("\n")
		}
		s.append(self.descriptionTabbedInner(tabCount))
		return s
	}
	
	override func successfulRoute(currentComponent: String, handler: RouteMap.RequestHandler, webResponse: WebResponse) -> RouteMap.RequestHandler {
		let request = webResponse.request
		if let decodedComponent = currentComponent.stringByDecodingURL {
			request.urlVariables[self.name] = decodedComponent
		} else {
			request.urlVariables[self.name] = currentComponent
		}
		return handler
	}
	
}








struct HTTPMethod {
    let methodString: String
    
    init(_ methodString: String) {
        self.methodString = methodString
    }
    
    static let GET = HTTPMethod("GET")
    static let POST = HTTPMethod("POST")
    static let PUT = HTTPMethod("PUT")
    static let PATCH = HTTPMethod("PATCH")
    static let DELETE = HTTPMethod("DELETE")
}



public final class Router: Responder {
    
    private let routeMatcher: RouteMatcher
    
    init(matcherType: RouteMatcher.Type, buildFunc: (RouterBuilder)->()) throws {
        let builder = RouterBuilder()
        buildFunc(builder)
        self.routeMatcher = try builder.build(matcherType)
    }
    
    
    func respond(to request: WebRequest) -> Response {
        
        return self.routeMatcher.matchRoute(request)
            .map { $0.handler.respond(request, params: $0.params) } ?? .InternalError("Handler not found")
    }
    
}

typealias HandlerGenerator = () -> RouteResponder


enum RouteMethodKey {
    case Any
    case Specific(HTTPMethod)
}

struct RouteKey {
    let method: RouteMethodKey
    let pattern: String
}


protocol RouteMatcher {
    
    init(routes: [RouteKey: HandlerGenerator]) throws
    func matchRoute(request: WebRequest) -> (handler: RouteResponder, params: [String:String])?
}

extension RouteMethodKey: Hashable {
    var hashValue: Int {
        switch self {
        case .Any: return 0
        case .Specific(let method): return method.methodString.hashValue
        }
    }
}

func ==(lhs: RouteMethodKey, rhs: RouteMethodKey) -> Bool {
    switch (lhs, rhs) {
    case (.Any, .Any): return true
    case (.Specific(let method1), .Specific(let method2)): return method1.methodString == method2.methodString
    default: return false
    }
}

extension RouteKey: Hashable {
    var hashValue: Int {
        return self.method.hashValue ^ self.pattern.hashValue
    }
}

func ==(lhs: RouteKey, rhs: RouteKey) -> Bool {
    return lhs.method == rhs.method && lhs.pattern == rhs.pattern
}

public class RouterBuilder {
    
    private var routes = [RouteKey: HandlerGenerator]()
    
    func addRoute(method: RouteMethodKey, pathPattern: String, handlerGenerator: HandlerGenerator) {
        routes[RouteKey(method: method, pattern: pathPattern)] = handlerGenerator
    }
    
    func addRoute(method: HTTPMethod, pathPattern: String, handlerGenerator: HandlerGenerator) {
        self.addRoute(.Specific(method), pathPattern: pathPattern, handlerGenerator: handlerGenerator)
    }
    
    func addRoute(methods: [HTTPMethod], pathPattern: String, handlerGenerator: HandlerGenerator) {
        for method in methods {
            self.addRoute(.Specific(method), pathPattern: pathPattern, handlerGenerator: handlerGenerator)
        }
    }
    
    private func build(matcherType: RouteMatcher.Type) throws -> RouteMatcher {
        return try matcherType.init(routes: self.routes)
    }
}

extension RouterBuilder {
    
    func GET(pattern: String, handler: RouteResponder) {
        self.addRoute(.GET, pathPattern: pattern) { handler }
    }
    
    func GET(pattern: String, handlerGenerator: () -> RouteResponder) {
        self.addRoute(.GET, pathPattern: pattern, handlerGenerator: handlerGenerator)
    }
    
    func POST(pattern: String, handlerGenerator: () -> RouteResponder) {
        self.addRoute(.POST, pathPattern: pattern, handlerGenerator: handlerGenerator)
    }
    
    func POST(pattern: String, handler: RouteResponder) {
        self.POST(pattern) { handler }
    }
    
    func DELETE(pattern: String, handlerGenerator: () -> RouteResponder) {
        self.addRoute(.DELETE, pathPattern: pattern, handlerGenerator: handlerGenerator)
    }
    
    func DELETE(pattern: String, handler: RouteResponder) {
        self.DELETE(pattern) { handler }
    }
    
    func PATCH(pattern: String, handlerGenerator: () -> RouteResponder) {
        self.addRoute(.PATCH, pathPattern: pattern, handlerGenerator: handlerGenerator)
    }
    
    func PATCH(pattern: String, handler: RouteResponder) {
        self.PATCH(pattern) { handler }
    }
    
    
}


protocol RouteResponder {
    func respond(request: WebRequest, params: [String:String]) -> Response
}


private protocol TrieNode: class {
    var children: [protocol<TrieNode, NonRootTrieNode>] { get set }
    var handler: HandlerGenerator? { get set}
    var path: [String] { get set }
    var segment: String { get }
    
    func matchPathSegment(path: String) -> Bool
    func updateContext(path: String, inout context: [String: String])
}

private protocol NonRootTrieNode {}

enum TrieNodeBuildError: ErrorType {
    case OverridingHandler
    case ConflictingRoutes(paths: [String])
    case EmptyRoutePath
}

extension TrieNode {
    
    
    func evaluate(pathSegments: [String], inout context: [String: String]) -> ([String:String], HandlerGenerator)? {
        
        var strippedPathSegments = pathSegments
        let segment = strippedPathSegments.removeFirst()
        
        if self.matchPathSegment(segment) {
            self.updateContext(segment, context: &context)
            if strippedPathSegments.count > 0 {
                for node in self.children {
                    if let (context, handler) = node.evaluate(strippedPathSegments, context: &context) {
                        return (context, handler)
                    }
                }
                return nil
            } else {
                return self.handler.map { (context, $0) }
            }
        } else {
            return nil
        }
    }
    
    
    func matchTrie(node: TrieNode) -> (TrieNode, TrieNode)? {
        if self.matchPathSegment(node.segment) || node.matchPathSegment(self.segment) {
            if node.children.count > 0 || self.children.count > 0 {
                var found:(TrieNode, TrieNode)? = nil
                for myChild in self.children {
                    for hisChild in node.children {
                        found = myChild.matchTrie(hisChild)
                        if found != nil { break }
                    }
                    if found != nil { break }
                }
                return found
            } else {
                return (self, node)
            }
        } else {
            return nil
        }
    }
    
    func addNode(newNode: protocol<TrieNode, NonRootTrieNode>) throws {
        
        newNode.setParentPath(self.path)
        
        for node in self.children {
            if let pair = newNode.matchTrie(node) {
                throw TrieNodeBuildError.ConflictingRoutes(paths: [
                    pair.0.path.joinWithSeparator("/"),
                    pair.1.path.joinWithSeparator("/")
                    ])
            }
        }
        self.children.append(newNode)
    }
    
    func setParentPath(path: [String]) {
        self.path = Array([path, [self.segment]].flatten())
        for child in self.children {
            child.setParentPath(self.path)
        }
    }
    
    func updateContext(path: String, inout context: [String: String]) {
        
    }
}

private extension TrieNode where Self: NonRootTrieNode {
    func addHandler(handler: HandlerGenerator, path: [String],
                    nodeBuilder: (path: String) -> protocol<TrieNode,NonRootTrieNode>) throws {
        var found = false
        if path.count == 0 {
            if self.handler != nil {
                throw TrieNodeBuildError.OverridingHandler
            }
            self.handler = handler
        } else {
            
            var newPath = path
            let firstComp = newPath.removeFirst()
            
            for child in self.children {
                if child.segment == firstComp {
                    try child.addHandler(handler, path: newPath, nodeBuilder: nodeBuilder)
                    found = true
                    break
                }
            }
            if !found {
                
                let node = nodeBuilder(path: firstComp)
                try node.addHandler(handler, path: newPath, nodeBuilder: nodeBuilder)
                try self.addNode(node)
            }
        }
    }
}


private class PathNode: TrieNode, NonRootTrieNode {
    
    private var path: [String]
    
    let segment: String
    var children: [protocol<TrieNode, NonRootTrieNode>] = []
    var handler: HandlerGenerator? = nil
    
    
    init(segment: String) {
        self.segment = segment
        self.path = [segment]
    }
    
    func matchPathSegment(segment: String) -> Bool {
        return self.segment == segment
    }
    
    
}



private class WildcardNode: TrieNode, NonRootTrieNode {
    var children: [protocol<TrieNode, NonRootTrieNode>] = []
    var handler: HandlerGenerator? = nil
    var segment: String {
        return "*"
    }
    
    var path: [String]
    
    init() {
        self.path = ["*"]
    }
    
    func matchPathSegment(path: String) -> Bool {
        return true
    }
}

private class VariableNode: TrieNode, NonRootTrieNode {
    let name: String
    var segment: String {
        return ":\(self.name)"
    }
    
    private var path: [String]
    
    var children: [protocol<TrieNode, NonRootTrieNode>] = []
    var handler: HandlerGenerator? = nil
    
    init(name: String) {
        self.name = name
        self.path = [":\(name)"]
    }
    
    func matchPathSegment(path: String) -> Bool {
        return true
    }
    
    func updateContext(path: String, inout context: [String: String]) {
        context[self.name] = path
    }
    
}

private class RootRouteNode: TrieNode {
    private var path: [String] = []
    var children: [protocol<TrieNode, NonRootTrieNode>] = []
    var handler: HandlerGenerator? = nil
    let segment: String = ""
    
    func matchPathSegment(path: String) -> Bool {
        return path == self.segment
    }
    
    func addHandler(method: RouteMethodKey,
                    path: [String],
                    handler: HandlerGenerator,
                    nodeBuilder: (path: String) -> protocol<TrieNode,NonRootTrieNode> ) throws {
        guard path.count > 0 else { throw TrieNodeBuildError.EmptyRoutePath }
        
        var methodNode: protocol<TrieNode, NonRootTrieNode> = RouteMethodNode(method: method)
        if let idx = (self.children.indexOf { $0.segment == methodNode.segment }) {
            methodNode = self.children[idx]
            try methodNode.addHandler(handler, path: path, nodeBuilder: nodeBuilder)
        } else {
            try methodNode.addHandler(handler, path: path, nodeBuilder: nodeBuilder)
            try self.addNode(methodNode)
        }
        
    }
}

private class RouteMethodNode: TrieNode, NonRootTrieNode {
    private var path: [String] = []
    var children: [protocol<TrieNode, NonRootTrieNode>] = []
    var handler: HandlerGenerator? = nil
    let methodSpec: RouteMethodKey
    
    static func segmentPresentation(methodKey: RouteMethodKey) -> String {
        switch methodKey {
        case .Any:
            return "AnyMethod"
        case .Specific(let method):
            return method.methodString
        }
    }
    
    var segment: String {
        return RouteMethodNode.segmentPresentation(self.methodSpec)
    }
    
    init(method: RouteMethodKey) {
        self.methodSpec = method
    }
    
    func matchPathSegment(path: String) -> Bool {
        switch self.methodSpec {
        case .Any: return true
        case .Specific(let method):
            return method.methodString.caseInsensitiveCompare(path) == .OrderedSame
        }
    }
    
}



final class PerfectRouteMatcher : RouteMatcher {
    
    private static func nodeForPathSegment(segment: String) -> protocol<TrieNode, NonRootTrieNode> {
        switch segment {
        case "*": return WildcardNode()
        case let s where s.utf8.count > 0 && s.substringToIndex(s.startIndex.advancedBy(1)) == ":" :
            return VariableNode(name: s.substringFromIndex(s.startIndex.advancedBy(1)))
        default: return PathNode(segment: segment)
        }
    }
    
    
    private let rootNode: TrieNode
    
    init(routes: [RouteKey : HandlerGenerator]) throws {
        
        let rootNode = RootRouteNode()
        for (routeKey, handler) in routes {
            
            let path = routeKey.pattern.componentsSeparatedByString("/").filter { $0 != "" }
            try rootNode.addHandler(routeKey.method,
                                    path: path,
                                    handler: handler,
                                    nodeBuilder: PerfectRouteMatcher.nodeForPathSegment)
        }
        self.rootNode = rootNode
    }
    
    func matchRoute(request: WebRequest) -> (handler: RouteResponder, params: [String:String])? {
        var context = [String: String]()
        let methodAndPath = Array([
            [""],
            [RouteMethodNode.segmentPresentation(.Specific(HTTPMethod(request.requestMethod!)))],
            request.path!.componentsSeparatedByString("/").filter { $0 != "" }
            ].flatten())
        return self.rootNode.evaluate(methodAndPath, context: &context)
            .map { ($0.1(), $0.0) }
    }
}


