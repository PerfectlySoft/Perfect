//
//  WebRequest.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/6/15.
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

/// Provides access to all incoming request data. Handles the following tasks:
///
/// * Parsing the incoming HTTP request
/// * Providing access to all HTTP headers & cookies
/// * Providing access to all meta headers which may have been added by the web server
/// * Providing access to GET & POST arguments
/// * Providing access to any file upload data
/// * Establishing the document root, from which response files are located
///
/// Access to the current WebRequest object is generally provided through the corresponding WebResponse object
public class WebRequest {
    /// HTTP request method types
    public enum Method: Hashable, CustomStringConvertible {
        /// OPTIONS
        case options,
        /// GET
        get,
        /// HEAD
        head,
        /// POST
        post,
        /// PUT
        put,
        /// DELETE
        delete,
        /// TRACE
        trace,
        /// CONNECT
        connect,
        /// Any unaccounted for or custom method
        custom(String)
        
        static func methodFrom(string: String) -> Method {
            
            switch string {
            case "OPTIONS": return .options
            case "GET":     return .get
            case "HEAD":    return .head
            case "POST":    return .post
            case "PUT":     return .put
            case "DELETE":  return .delete
            case "TRACE":   return .trace
            case "CONNECT": return .connect
            default:        return .custom(string)
            }
        }
        
        /// Method String hash value
        public var hashValue: Int {
            return self.description.hashValue
        }
        
        /// The method as a String
        public var description: String {
            switch self {
            case .options:  return "OPTIONS"
            case .get:      return "GET"
            case .head:     return "HEAD"
            case .post:     return "POST"
            case .put:      return "PUT"
            case .delete:   return "DELETE"
            case .trace:    return "TRACE"
            case .connect:  return "CONNECT"
            case .custom(let s): return s
            }
        }
    }
    
	var connection: WebConnection
    
    init(_ c: WebConnection) {
        self.connection = c
    }
    
    /// The web server's document root
	public lazy var documentRoot: String = {
        let c = self.connection
        if let root = c.requestParams["PERFECTSERVER_DOCUMENT_ROOT"] {
            return root
        } else if let root = c.requestParams["DOCUMENT_ROOT"] {
            return root
        }
        return ""
	}()

	private var cachedHttpAuthorization: [String:String]? = nil

	/// Variables set by the URL routing process
	public var urlVariables = [String:String]()

	/// A `Dictionary` containing all HTTP header names and values
	/// Only HTTP headers are included in the result. Any "meta" headers, i.e. those provided by the web server, are discarded.
	public lazy var headers: [String:String] = {
        var d = [String:String]()
        for (key, value) in self.connection.requestParams
            where key.begins(with: "HTTP_") {
            let index = key.index(key.startIndex, offsetBy: 5)
            let nKey = key[index..<key.endIndex].stringByReplacing(string: "_", withString: "-")
            d[nKey] = value
        }
        return d
    }()

    private func bSplit(_ c: String.CharacterView, on: Character) -> [String.CharacterView] {
        return c.split(separator: on, maxSplits: Int.max, omittingEmptySubsequences: false)
    }
    
    private func toValidPairs(_ a: [[String.CharacterView]]) -> [(String, String)] {
        let valueUp = a.filter {
                $0.count == 2
            }.map {
                (String($0[0]).stringByDecodingURL ?? "", String($0[1]).stringByDecodingURL ?? "")
            }
        return valueUp.filter {
            !$0.0.isEmpty
        }
    }
    
	/// A tuple array containing each incoming cookie name/value pair
	public lazy var cookies: [(String, String)] = {
        guard let qs = self.httpCookie else {
            return [(String, String)]()
        }
        // chaining this properly breaks swift
        let eqSplit = qs.characters.split(separator: ";").map {
            (chars: String.CharacterView) in String(chars.filter { $0 != " " })
        }.map {
            self.bSplit($0.characters, on: "=")
        }
        return self.toValidPairs(eqSplit)
	}()

	/// A tuple array containing each GET/search/query parameter name/value pair
	public lazy var queryParams: [(String, String)] = {
		guard let qs = self.queryString else {
            return [(String, String)]()
        }
        // chaining this properly breaks swift
        let eqSplit = qs.characters.split(separator: "&").map {
            self.bSplit($0, on: "=")
        }
        return self.toValidPairs(eqSplit)
	}()

	/// An array of `MimeReader.BodySpec` objects which provide access to each file which was uploaded
	public lazy var fileUploads: [MimeReader.BodySpec] = {
        if let mime = self.connection.mimes {
            return mime.bodySpecs.filter { $0.file != nil }
        }
        return Array<MimeReader.BodySpec>()
	}()

	/// Return the raw POST body as a byte array
	/// This is mainly useful when POSTing non-url-encoded and not-multipart form data
	/// For example, if the content-type were application/json you could use this function to get the raw JSON data as bytes
	public lazy var postBodyBytes: [UInt8] = {
		return self.connection.stdin ?? [UInt8]()
	}()

	/// Return the raw POST body as a String
	/// This is mainly useful when POSTing non-url-encoded and not-multipart form data
	/// For example, if the content-type were application/json you could use this function to get the raw JSON data as a String
	public lazy var postBodyString: String = {
		if let stdin = self.connection.stdin {
			return UTF8Encoding.encode(bytes: stdin)
		}
		return ""
	}()

	/// A tuple array containing each POST parameter name/value pair
	public lazy var postParams: [(String, String)] = {
		if let mime = self.connection.mimes {
            return mime.bodySpecs.filter { $0.file == nil }.map { ($0.fieldName, $0.fieldValue) }
		} else if let stdin = self.connection.stdin {
			let qs = UTF8Encoding.encode(bytes: stdin)
            let eqSplit = qs.characters.split(separator: "&").map {
                self.bSplit($0, on: "=")
            }
            return self.toValidPairs(eqSplit)
		}
        return [(String, String)]()
    }()

	/// Returns the first GET or POST parameter with the given name
	/// Returns the supplied default value if the parameter was not found
	public func param(name: String, defaultValue: String? = nil) -> String? {
		for p in self.queryParams
			where p.0 == name {
				return p.1
		}
		for p in self.postParams
			where p.0 == name {
				return p.1
		}
		return defaultValue
	}

	/// Returns all GET or POST parameters with the given name
	public func params(named: String) -> [String] {
        let a = self.params().filter { $0.0 == named }.map { $0.1 }
		return a
	}

	/// Returns all GET or POST parameters
	public func params() -> [(String, String)] {
		let a = self.queryParams + self.postParams
		return a
	}

	private func get(_ named: String) -> String? {
		return connection.requestParams[named]
	}

	private func set(_ named: String, value: String?) {
		if let v = value {
			connection.requestParams[named] = v
		} else {
			connection.requestParams.removeValue(forKey: named)
		}
	}

	private func get(_ named: String) -> Int? {
		if let i = connection.requestParams[named] {
			return Int(i)
		}
		return nil
	}

	private func set(_ named: String, value: Int?) {
		if let v = value {
			connection.requestParams[named] = String(v)
		} else {
			connection.requestParams.removeValue(forKey: named)
		}
	}

	/// Provides access to the HTTP_CONNECTION parameter.
	public var httpConnection: String? { get { return get("HTTP_CONNECTION") } set { set("HTTP_CONNECTION", value: newValue) } }
	/// Provides access to the HTTP_COOKIE parameter.
	public var httpCookie: String? { get { return get("HTTP_COOKIE") } set { set("HTTP_COOKIE", value: newValue) } }
	/// Provides access to the HTTP_HOST parameter.
	public var httpHost: String? { get { return get("HTTP_HOST") } set { set("HTTP_HOST", value: newValue) } }
	/// Provides access to the HTTP_USER_AGENT parameter.
	public var httpUserAgent: String? { get { return get("HTTP_USER_AGENT") } set { set("HTTP_USER_AGENT", value: newValue) } }
	/// Provides access to the HTTP_CACHE_CONTROL parameter.
	public var httpCacheControl: String? { get { return get("HTTP_CACHE_CONTROL") } set { set("HTTP_CACHE_CONTROL", value: newValue) } }
	/// Provides access to the HTTP_REFERER parameter.
	public var httpReferer: String? { get { return get("HTTP_REFERER") } set { set("HTTP_REFERER", value: newValue) } }
	/// Provides access to the HTTP_REFERER parameter but using the proper "referrer" spelling for pedants.
	public var httpReferrer: String? { get { return get("HTTP_REFERER") } set { set("HTTP_REFERER", value: newValue) } }
	/// Provides access to the HTTP_ACCEPT parameter.
	public var httpAccept: String? { get { return get("HTTP_ACCEPT") } set { set("HTTP_ACCEPT", value: newValue) } }
	/// Provides access to the HTTP_ACCEPT_ENCODING parameter.
	public var httpAcceptEncoding: String? { get { return get("HTTP_ACCEPT_ENCODING") } set { set("HTTP_ACCEPT_ENCODING", value: newValue) } }
	/// Provides access to the HTTP_ACCEPT_LANGUAGE parameter.
	public var httpAcceptLanguage: String? { get { return get("HTTP_ACCEPT_LANGUAGE") } set { set("HTTP_ACCEPT_LANGUAGE", value: newValue) } }
	/// Provides access to the HTTP_AUTHORIZATION with all elements having been parsed using the `String.parseAuthentication` extension function.
	public var httpAuthorization: [String:String] {
		guard cachedHttpAuthorization == nil else {
			return cachedHttpAuthorization!
		}
		let auth = connection.requestParams["HTTP_AUTHORIZATION"] ?? connection.requestParams["Authorization"] ?? ""
		var ret = auth.parseAuthentication()
		if ret.count > 0 {
			ret["method"] = self.requestMethod.description
		}
		self.cachedHttpAuthorization = ret
		return ret
	}
	/// Provides access to the CONTENT_LENGTH parameter.
	public var contentLength: Int? { get { return get("CONTENT_LENGTH") } set { set("CONTENT_LENGTH", value: newValue) } }
	/// Provides access to the CONTENT_TYPE parameter.
	public var contentType: String? { get { return get("CONTENT_TYPE") } set { set("CONTENT_TYPE", value: newValue) } }
	/// Provides access to the PATH parameter.
	public var path: String? { get { return get("PATH") } set { set("PATH", value: newValue) } }
	/// Provides access to the PATH_TRANSLATED parameter.
	public var pathTranslated: String? { get { return get("PATH_TRANSLATED") } set { set("PATH_TRANSLATED", value: newValue) } }
	/// Provides access to the QUERY_STRING parameter.
	public var queryString: String? { get { return get("QUERY_STRING") } set { set("QUERY_STRING", value: newValue) } }
	/// Provides access to the REMOTE_ADDR parameter.
	public var remoteAddr: String? { get { return get("REMOTE_ADDR") } set { set("REMOTE_ADDR", value: newValue) } }
	/// Provides access to the REMOTE_PORT parameter.
	public var remotePort: Int? { get { return get("REMOTE_PORT") } set { set("REMOTE_PORT", value: newValue) } }
	/// Provides access to the REQUEST_METHOD parameter.
	public var requestMethod: Method {
        get {
            return Method.methodFrom(string: get("REQUEST_METHOD") ?? "GET")
        }
        set {
            set("REQUEST_METHOD", value: newValue.description)
        }
    }
	/// Provides access to the REQUEST_URI parameter.
	public var requestURI: String? { get { return get("REQUEST_URI") } set { set("REQUEST_URI", value: newValue) } }
	/// Provides access to the SCRIPT_FILENAME parameter.
	public var scriptFilename: String? { get { return get("SCRIPT_FILENAME") } set { set("SCRIPT_FILENAME", value: newValue) } }
	/// Provides access to the SCRIPT_NAME parameter.
	public var scriptName: String? { get { return get("SCRIPT_NAME") } set { set("SCRIPT_NAME", value: newValue) } }
	/// Provides access to the SCRIPT_URI parameter.
	public var scriptURI: String? { get { return get("SCRIPT_URI") } set { set("SCRIPT_URI", value: newValue) } }
	/// Provides access to the SCRIPT_URL parameter.
	public var scriptURL: String? { get { return get("SCRIPT_URL") } set { set("SCRIPT_URL", value: newValue) } }
	/// Provides access to the SERVER_ADDR parameter.
	public var serverAddr: String? { get { return get("SERVER_ADDR") } set { set("SERVER_ADDR", value: newValue) } }
	/// Provides access to the SERVER_ADMIN parameter.
	public var serverAdmin: String? { get { return get("SERVER_ADMIN") } set { set("SERVER_ADMIN", value: newValue) } }
	/// Provides access to the SERVER_NAME parameter.
	public var serverName: String? { get { return get("SERVER_NAME") } set { set("SERVER_NAME", value: newValue) } }
	/// Provides access to the SERVER_PORT parameter.
	public var serverPort: Int? { get { return get("SERVER_PORT") } set { set("SERVER_PORT", value: newValue) } }
	/// Provides access to the SERVER_PROTOCOL parameter.
	public var serverProtocol: String? { get { return get("SERVER_PROTOCOL") } set { set("SERVER_PROTOCOL", value: newValue) } }
	/// Provides access to the SERVER_SIGNATURE parameter.
	public var serverSignature: String? { get { return get("SERVER_SIGNATURE") } set { set("SERVER_SIGNATURE", value: newValue) } }
	/// Provides access to the SERVER_SOFTWARE parameter.
	public var serverSoftware: String? { get { return get("SERVER_SOFTWARE") } set { set("SERVER_SOFTWARE", value: newValue) } }
	/// Provides access to the PATH_INFO parameter if it exists or else the SCRIPT_NAME parameter.
	public var pathInfo: String? { get { return get("PATH_INFO") ?? get("SCRIPT_NAME") } set { set("PATH_INFO", value: newValue) } }
	/// Provides access to the GATEWAY_INTERFACE parameter.
	public var gatewayInterface: String? { get { return get("GATEWAY_INTERFACE") } set { set("GATEWAY_INTERFACE", value: newValue) } }
	/// Returns true if the request was encrypted over HTTPS.
	public var isHttps: Bool {
		get {
			return "on" == get("HTTPS")
		}
		set {
			set("HTTPS", value: newValue ? "on" : nil)
		}
	}
	/// Returns the indicated HTTP header.
	public func header(named: String) -> String? { return self.headers[named.uppercased()] }
	/// Returns the raw request parameter header
	public func rawHeader(named: String) -> String? { return self.connection.requestParams[named] }
	/// Returns a Dictionary containing all raw request parameters.
    public var rawHeaders: [String:String] { return self.connection.requestParams }
}

/// Compare two request methods
public func == (lhs: WebRequest.Method, rhs: WebRequest.Method) -> Bool {
    return lhs.description == rhs.description
}
