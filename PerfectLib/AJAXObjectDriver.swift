//
//  AJAXObjectDriver.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2015-08-10.
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

let actionParamName = "_action"

/// This client-side class handles access to the AJAX/XHR API.
/// It provides facilities for setting up the parameters for the raw requests
public class AJAXObjectDriver : PerfectObjectDriver {
	
	let endpointBase: String
	let fileExtension: String
	public let curl = CURL()
	
	public init(endpointBase: String, fileExtension: String = ".mustache") {
		self.endpointBase = endpointBase
		self.fileExtension = fileExtension
	}
	
	public func close() {
		self.curl.close()
	}
	
	// protected!
	public func performRequest(uri: String) -> (Int, String, String) {
		self.curl.url = uri
		let (code, head, body) = curl.performFully()
		if code == 0 {
			let responseCode = curl.responseCode
			return (responseCode, UTF8Encoding.encode(head), UTF8Encoding.encode(body))
		}
		return (code, UTF8Encoding.encode(head), UTF8Encoding.encode(body))
	}
	
	public func load<T : PerfectObject>(type: T, withId: uuid_t) -> T {
		let fileName = type.simpleName() + self.fileExtension
		var url = self.endpointBase + fileName + "?" + actionParamName + "=" + HandlerAction.Load.asString()
		url.appendContentsOf("&" + type.primaryKeyName().stringByEncodingURL + "=" + String.fromUUID(withId).stringByEncodingURL)
		
		let (code, _, bodyStr) = self.performRequest(url)
		if code == 200 {
			do {
				if let deJason = try JSONDecode().decode(bodyStr) as? JSONDictionaryType {
					let dictionary = deJason.dictionary
					if let resultSets = dictionary["resultSets"] as? JSONArrayType {
						if let results = resultSets.array.first as? JSONDictionaryType {
							let innerDictionary = results.dictionary
							let possibleFields = type.fieldList()
							var newDict = [String:String]()
							for (n, v) in innerDictionary {
								if possibleFields.contains(n) {
									newDict[n] = "\(v)"
								}
							}
							type.load(newDict)
						}
					}
				}
			} catch {
				
			}
		}
		return type
	}
	
	public func load<T : PerfectObject>(type: T, withUniqueField: (String,String)) -> T {
		let fileName = type.simpleName() + self.fileExtension
		var url = self.endpointBase + fileName + "?" + actionParamName + "=" + HandlerAction.Load.asString()
		url.appendContentsOf("&" + withUniqueField.0.stringByEncodingURL + "=" + withUniqueField.1.stringByEncodingURL)
		
		let (code, _, bodyStr) = self.performRequest(url)
		if code == 200 {
			do {
				if let deJason = try JSONDecode().decode(bodyStr) as? JSONDictionaryType {
					let dictionary = deJason.dictionary
					if let resultSets = dictionary["resultSets"] as? JSONArrayType {
						if let results = resultSets.array.first as? JSONDictionaryType {
							let innerDictionary = results.dictionary
							let possibleFields = type.fieldList()
							var newDict = [String:String]()
							for (n, v) in innerDictionary {
								if possibleFields.contains(n) {
									newDict[n] = "\(v)"
								}
							}
							type.load(newDict)
						}
					}
				}
			} catch {
				
			}
		}
		return type
	}
	
	public func delete(type: PerfectObject) -> (Int, String) {
		let fileName = type.simpleName() + self.fileExtension
		var url = self.endpointBase + fileName + "?" + actionParamName + "=" + HandlerAction.Delete.asString()
		url.appendContentsOf("&" + type.primaryKeyName().stringByEncodingURL + "=" + String.fromUUID(type.objectId()).stringByEncodingURL)
		
		let (code, _, bodyStr) = self.performRequest(url)
		if code == 200 {
			do {
				if let deJason = try JSONDecode().decode(bodyStr) as? JSONDictionaryType {
					let dictionary = deJason.dictionary
					let resultMsg = dictionary["resultMsg"] as? String ?? "Invalid response"
					let resultCode = Int(dictionary["resultCode"] as? String ?? "-1")!
					return (resultCode, resultMsg)
				}
			} catch {
				
			}
		}
		return (-1, "Invalid response")
	}
	
	public func commitChanges(type: PerfectObject) -> (Int, String) {
		let fileName = type.simpleName() + self.fileExtension
		var url = self.endpointBase + fileName + "?" + actionParamName + "=" + HandlerAction.Commit.asString()
		url.appendContentsOf("&" + type.primaryKeyName().stringByEncodingURL + "=" + String.fromUUID(type.objectId()).stringByEncodingURL)
		
		let withFields = type.unloadDirty()
		for (n, v) in withFields {
			url.appendContentsOf("&" + n.stringByEncodingURL + "=" + v.stringByEncodingURL)
		}
		
		let (code, _, bodyStr) = self.performRequest(url)
		if code == 200 {
			do {
				if let deJason = try JSONDecode().decode(bodyStr) as? JSONDictionaryType {
					let dictionary = deJason.dictionary
					let resultMsg = dictionary["resultMsg"] as? String ?? "Invalid response"
					let resultCode = Int(dictionary["resultCode"] as? String ?? "-1")!
					return (resultCode, resultMsg)
				}
			} catch {
				
			}
		}
		return (-1, "Invalid response")
	}
	
	// !FIX! optimize this so that it can accomplish the updates in one request
	public func commitChanges(types: [PerfectObject]) -> [(Int, String)] {
		return types.map { self.commitChanges($0) }
	}
	
	public func create<T : PerfectObject>(withFields: [(String,String)]) -> T {
		let t = T(driver: self)
		let fileName = t.simpleName() + self.fileExtension
		var url = self.endpointBase + fileName + "?" + actionParamName + "=" + HandlerAction.Create.asString()
		
		for (n, v) in withFields {
			url.appendContentsOf("&" + n.stringByEncodingURL + "=" + v.stringByEncodingURL)
		}
		
		let (code, _, bodyStr) = self.performRequest(url)
		if code == 200 {
			do {
				if let deJason = try JSONDecode().decode(bodyStr) as? JSONDictionaryType {
					let dictionary = deJason.dictionary
					if let resultSets = dictionary["resultSets"] as? JSONArrayType {
						if let results = resultSets.array.first as? JSONDictionaryType {
							let innerDictionary = results.dictionary
							let possibleFields = t.fieldList()
							var newDict = [String:String]()
							for (n, v) in innerDictionary {
								if possibleFields.contains(n) {
									newDict[n] = "\(v)"
								}
							}
							t.load(newDict)
						}
					}
				}
			} catch {
				
			}
		}
		return t
	}
	
	public func joinTable<T : PerfectObject>(type: PerfectObject, name: String) -> [T] {
		let keyField = "id_" + type.simpleName()
		let ret:[T] = self.list((keyField, String.fromUUID(type.objectId())))
		return ret
	}
	
	public func list<T : PerfectObject>() -> [T] {
		var returning = [T]()
		var t = T(driver: self)
		let fileName = t.simpleName() + self.fileExtension
		let url = self.endpointBase + fileName + "?" + actionParamName + "=" + HandlerAction.List.asString()
		
		let (code, _, bodyStr) = self.performRequest(url)
		if code == 200 {
			do {
				if let deJason = try JSONDecode().decode(bodyStr) as? JSONDictionaryType {
					let dictionary = deJason.dictionary
					if let resultSets = dictionary["resultSets"] as? JSONArrayType {
						for resultSet in resultSets.array {
							if let results = resultSet as? JSONDictionaryType {
								let innerDictionary = results.dictionary
								let possibleFields = t.fieldList()
								var newDict = [String:String]()
								for (n, v) in innerDictionary {
									if possibleFields.contains(n) {
										newDict[n] = "\(v)"
									}
								}
								t.load(newDict)
								returning.append(t)
								t = T(driver: self)
							}
						}
					}
				}
			} catch {
				
			}
		}
		return returning
	}
	
	public func list<T : PerfectObject>(withCriterion: (String,String)) -> [T] {
		var returning = [T]()
		var t = T(driver: self)
		let fileName = t.simpleName() + self.fileExtension
		let url = self.endpointBase + fileName + "?" + actionParamName + "=" + HandlerAction.List.asString() +
			"&" + withCriterion.0.stringByEncodingURL + "=" + withCriterion.1.stringByEncodingURL
		
		let (code, _, bodyStr) = self.performRequest(url)
		if code == 200 {
			do {
				if let deJason = try JSONDecode().decode(bodyStr) as? JSONDictionaryType {
					let dictionary = deJason.dictionary
					if let resultSets = dictionary["resultSets"] as? JSONArrayType {
						for resultSet in resultSets.array {
							if let results = resultSet as? JSONDictionaryType {
								let innerDictionary = results.dictionary
								let possibleFields = t.fieldList()
								var newDict = [String:String]()
								for (n, v) in innerDictionary {
									if possibleFields.contains(n) {
										newDict[n] = "\(v)"
									}
								}
								t.load(newDict)
								returning.append(t)
								t = T(driver: self)
							}
						}
					}
				}
			} catch {
				
			}
		}
		return returning
	}
}






