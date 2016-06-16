//
//  NotificationPusher.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2016-02-16.
//  Copyright © 2016 PerfectlySoft. All rights reserved.
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

import PerfectNet
import PerfectThread

/**
Example code:

    // BEGIN one-time initialization code

    let configurationName = "My configuration name - can be whatever"

    NotificationPusher.addConfigurationIOS(configurationName) {
        (net:NetTCPSSL) in

        // This code will be called whenever a new connection to the APNS service is required.
        // Configure the SSL related settings.

        net.keyFilePassword = "if you have password protected key file"

        guard net.useCertificateChainFile("path/to/entrust_2048_ca.cer") &&
            net.useCertificateFile("path/to/aps_development.pem") &&
            net.usePrivateKeyFile("path/to/key.pem") &&
            net.checkPrivateKey() else {

            let code = Int32(net.errorCode())
            print("Error validating private key file: \(net.errorStr(code))")
            return
        }
    }

    NotificationPusher.development = true // set to toggle to the APNS sandbox server

    // END one-time initialization code

    // BEGIN - individual notification push

    let deviceId = "hex string device id"
    let ary = [IOSNotificationItem.AlertBody("This is the message"), IOSNotificationItem.Sound("default")]
    let n = NotificationPusher()

    n.apnsTopic = "com.company.my-app"

    n.pushIOS(configurationName, deviceToken: deviceId, expiration: 0, priority: 10, notificationItems: ary) {
        response in

        print("NotificationResponse: \(response.code) \(response.body)")
    }

    // END - individual notification push

*/

/// Items to configure an individual notification push.
/// These correspond to what is described here:
/// https://developer.apple.com/library/mac/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/Chapters/TheNotificationPayload.html
public enum IOSNotificationItem {
    /// alert body child property
	case alertBody(String)
    /// alert title child property
	case alertTitle(String)
    /// alert title-loc-key
	case alertTitleLoc(String, [String]?)
    /// alert action-loc-key
	case alertActionLoc(String)
    /// alert loc-key
	case alertLoc(String, [String]?)
    /// alert launch-image
	case alertLaunchImage(String)
    /// aps badge key
	case badge(Int)
    /// aps sound key
	case sound(String)
    /// aps content-available key
	case contentAvailable
    /// aps category key
	case category(String)
    /// custom payload data
	case customPayload(String, Any)
}

enum IOSItemId: UInt8 {
	case deviceToken = 1
	case payload = 2
	case notificationIdentifier = 3
	case expirationDate = 4
	case priority = 5
}

private let iosDeviceIdLength = 32
private let iosNotificationCommand = UInt8(2)
private let iosNotificationPort = UInt16(443)
private let iosNotificationDevelopmentHost = "api.development.push.apple.com"
private let iosNotificationProductionHost = "api.push.apple.com"

struct IOSNotificationError {
	let code: UInt8
	let identifier: UInt32
}

class NotificationConfiguration {
	
	let configurator: NotificationPusher.netConfigurator
	let lock = Threading.Lock()
	var streams = [NotificationHTTP2Client]()
	
	init(configurator: NotificationPusher.netConfigurator) {
		self.configurator = configurator
	}
}

class NotificationHTTP2Client: HTTP2Client {
	let id: Int
	
	init(id: Int) {
		self.id = id
	}
}

/// The response object given after a push attempt.
public struct NotificationResponse {
	/// The response code for the request.
	public let code: Int
	/// The response body data bytes.
	public let body: [UInt8]
	/// The body data bytes interpreted as JSON and decoded into a Dictionary.
	public var jsonObjectBody: [String:Any] {
		do {
			if let json = try self.stringBody.jsonDecode() as? [String:Any] {
				return json
			}
		}
		catch {}
		return [String:Any]()
	}
	/// The body data bytes converted to String.
	public var stringBody: String {
		return UTF8Encoding.encode(bytes: self.body)
	}
}

/// The interface for APNS notifications.
public class NotificationPusher {
	
	typealias ComponentGenerator = IndexingIterator<[String]>
	
	/// On-demand configuration for SSL related functions.
	public typealias netConfigurator = (NetTCPSSL) -> ()
	
	/// Toggle development or production on a global basis.
	public static var development = false

	/// Sets the apns-topic which will be used for iOS notifications.
	public var apnsTopic: String?

	var responses = [NotificationResponse]()
	
	static var idCounter = 0
	
	static var notificationHostIOS: String {
		if self.development {
			return iosNotificationDevelopmentHost
		}
		return iosNotificationProductionHost
	}
	
	static let configurationsLock = Threading.Lock()
	static var iosConfigurations = [String:NotificationConfiguration]()
	static var activeStreams = [Int:NotificationHTTP2Client]()
	
	/// Add a configuration given a name and a callback.
	/// A particular configuration will generally correspond to an individual app.
	/// The configuration callback will be called each time a new connection is initiated to the APNS.
	/// Within the callback you will want to set:
	/// 1. Path to chain file as provided by Apple: net.useCertificateChainFile("path/to/entrust_2048_ca.cer")
	/// 2. Path to push notification certificate as obtained from Apple: net.useCertificateFile("path/to/aps.pem")
	/// 3a. Password for the certificate's private key file, if it is password protected: net.keyFilePassword = "password"
	/// 3b. Path to the certificate's private key file: net.usePrivateKeyFile("path/to/key.pem")
	public static func addConfigurationIOS(name nam: String, configurator: netConfigurator) {
		self.configurationsLock.doWithLock {
			self.iosConfigurations[nam] = NotificationConfiguration(configurator: configurator)
		}
	}
	
	static func getStreamIOS(configurationName configuration: String, callback: (HTTP2Client?) -> ()) {
		
		var conf: NotificationConfiguration?
		self.configurationsLock.doWithLock {
			conf = self.iosConfigurations[configuration]
		}
		
		if let c = conf {
			
			var net: NotificationHTTP2Client?
			var needsConnect = false
			c.lock.doWithLock {
				if c.streams.count > 0 {
					net = c.streams.removeLast()
				} else {
					needsConnect = true
					net = NotificationHTTP2Client(id: idCounter)
					activeStreams[idCounter] = net
					idCounter = idCounter &+ 1
				}
			}
			
			if !needsConnect {
				callback(net!)
			} else {
				// add a new connected stream
				
				c.configurator(net!.net)
				net!.connect(host: self.notificationHostIOS, port: iosNotificationPort, ssl: true, timeoutSeconds: 5.0) {
					b in
					if b {
						callback(net!)
					} else {
						callback(nil)
					}
				}
			}
			
		} else {
			callback(nil)
		}
	}
	
	static func releaseStreamIOS(configurationName configuration: String, net: HTTP2Client) {
		var conf: NotificationConfiguration?
		self.configurationsLock.doWithLock {
			conf = self.iosConfigurations[configuration]
		}
		
		if let c = conf, n = net as? NotificationHTTP2Client {
			
			c.lock.doWithLock {
				activeStreams.removeValue(forKey: n.id)
				if net.isConnected {
					c.streams.append(n)
				}
			}
			
		} else {
			net.close()
		}
	}
	
    /// Public initializer
	public init() {

	}

	/// Initialize given iOS apns-topic string.
	/// This can be set after initialization on the X.apnsTopic property.
	public init(apnsTopic: String) {
		self.apnsTopic = apnsTopic
	}

	func resetResponses() {
		self.responses.removeAll()
	}
	
	/// Push one message to one device.
	/// Provide the previously set configuration name, device token.
	/// Provide the expiration and priority as described here:
	///		https://developer.apple.com/library/mac/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/Chapters/APNsProviderAPI.html
	/// Provide a list of IOSNotificationItems.
	/// Provide a callback with which to receive the response.
	public func pushIOS(configurationName: String, deviceToken: String, expiration: UInt32, priority: UInt8, notificationItems: [IOSNotificationItem], callback: (NotificationResponse) -> ()) {
		
		NotificationPusher.getStreamIOS(configurationName: configurationName) {
			client in
			if let c = client {
				self.pushIOS(c, deviceTokens: [deviceToken], expiration: expiration, priority: priority, notificationItems: notificationItems) {
					responses in
					
					NotificationPusher.releaseStreamIOS(configurationName: configurationName, net: c)
					
					if responses.count == 1 {
						callback(responses.first!)
					} else {
						callback(NotificationResponse(code: -1, body: [UInt8]()))
					}
				}
			} else {
				callback(NotificationResponse(code: -1, body: [UInt8]()))
			}
		}
	}
	
	/// Push one message to multiple devices.
	/// Provide the previously set configuration name, and zero or more device tokens. The same message will be sent to each device.
	/// Provide the expiration and priority as described here:
	///		https://developer.apple.com/library/mac/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/Chapters/APNsProviderAPI.html
	/// Provide a list of IOSNotificationItems.
	/// Provide a callback with which to receive the responses.
	public func pushIOS(configurationName: String, deviceTokens: [String], expiration: UInt32, priority: UInt8, notificationItems: [IOSNotificationItem], callback: ([NotificationResponse]) -> ()) {
		
		NotificationPusher.getStreamIOS(configurationName: configurationName) {
			client in
			if let c = client {
				self.pushIOS(c, deviceTokens: deviceTokens, expiration: expiration, priority: priority, notificationItems: notificationItems) {
					responses in
					
					NotificationPusher.releaseStreamIOS(configurationName: configurationName, net: c)
					
					if responses.count == 1 {
						callback(responses)
					} else {
						callback([NotificationResponse(code: -1, body: [UInt8]())])
					}
				}
			} else {
				callback([NotificationResponse(code: -1, body: [UInt8]())])
			}
		}
	}
	
	func pushIOS(_ net: HTTP2Client, deviceToken: String, expiration: UInt32, priority: UInt8, notificationJson: [UInt8], callback: (NotificationResponse) -> ()) {
		
		let request = net.createRequest()
		request.requestMethod = .post
		request.postBodyBytes = notificationJson
		request.headers["content-type"] = "application/json; charset=utf-8"
		request.headers["apns-expiration"] = "\(expiration)"
		request.headers["apns-priority"] = "\(priority)"
		if let apnsTopic = apnsTopic {
			request.headers["apns-topic"] = apnsTopic
		}
		request.requestURI = "/3/device/\(deviceToken)"
		net.sendRequest(request) {
			response, msg in
			
			if let r = response {
				let code = r.getStatus().0
				callback(NotificationResponse(code: code, body: r.bodyData))
			} else {
				callback(NotificationResponse(code: -1, body: UTF8Encoding.decode(string: "No response")))
			}
		}
	}
	
	func pushIOS(_ client: HTTP2Client, deviceTokens: ComponentGenerator, expiration: UInt32, priority: UInt8, notificationJson: [UInt8], callback: ([NotificationResponse]) -> ()) {
		var g = deviceTokens
		if let next = g.next() {
			pushIOS(client, deviceToken: next, expiration: expiration, priority: priority, notificationJson: notificationJson) {
				response in
				
				self.responses.append(response)
				
				self.pushIOS(client, deviceTokens: g, expiration: expiration, priority: priority, notificationJson: notificationJson, callback: callback)
			}
		} else {
			callback(self.responses)
		}
	}
	
	func pushIOS(_ client: HTTP2Client, deviceTokens: [String], expiration: UInt32, priority: UInt8, notificationItems: [IOSNotificationItem], callback: ([NotificationResponse]) -> ()) {
		self.resetResponses()
		let g = deviceTokens.makeIterator()
		let jsond = UTF8Encoding.decode(string: self.itemsToPayloadString(notificationItems: notificationItems))
		self.pushIOS(client, deviceTokens: g, expiration: expiration, priority: priority, notificationJson: jsond, callback: callback)
	}
	
	func itemsToPayloadString(notificationItems items: [IOSNotificationItem]) -> String {
		var dict = [String:Any]()
		var aps = [String:Any]()
		var alert = [String:Any]()
		var alertBody: String?
		
		for item in items {
			switch item {
			case .alertBody(let s):
				alertBody = s
			case .alertTitle(let s):
				alert["title"] = s
			case .alertTitleLoc(let s, let a):
				alert["title-loc-key"] = s
				if let titleLocArgs = a {
					alert["title-loc-args"] = titleLocArgs
				}
			case .alertActionLoc(let s):
				alert["action-loc-key"] = s
			case .alertLoc(let s, let a):
				alert["loc-key"] = s
				if let locArgs = a {
					alert["loc-args"] = locArgs
				}
			case .alertLaunchImage(let s):
				alert["launch-image"] = s
			case .badge(let i):
				aps["badge"] = i
			case .sound(let s):
				aps["sound"] = s
			case .contentAvailable:
				aps["content-available"] = 1
			case .category(let s):
				aps["category"] = s
			case .customPayload(let s, let a):
				dict[s] = a
			}
		}
		
		if let ab = alertBody {
			if alert.count == 0 { // just a string alert
				aps["alert"] = ab
			} else { // a dict alert
				alert["body"] = ab
				aps["alert"] = alert
			}
		}
		
		dict["aps"] = aps
		do {
			return try dict.jsonEncodedString()
		}
		catch {}
		return "{}"
	}
}

private func jsonSerialize(o: Any) -> String? {
	do {
		return try jsonEncodedStringWorkAround(o)
	} catch let e as JSONConversionError {
		print("Could not convert to JSON: \(e)")
	} catch {}
	return nil
}
