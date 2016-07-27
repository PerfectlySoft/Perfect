# Perfect: Server-Side Swift
[![Perfect logo](http://www.perfect.org/images/perfect-git-banner.png)](http://perfect.org/get-involved.html)

[![Swift 3.0](https://img.shields.io/badge/Swift-3.0-orange.svg?style=flat)](https://developer.apple.com/swift/)
[![Platforms OS X | Linux](https://img.shields.io/badge/Platforms-OS%20X%20%7C%20Linux%20-lightgray.svg?style=flat)](https://developer.apple.com/swift/)
[![License Apache](https://img.shields.io/badge/License-Apache-lightgrey.svg?style=flat)](http://perfect.org/licensing.html)
[![Docs](https://img.shields.io/badge/docs-99%25-yellow.svg?style=flat)](http://www.perfect.org/docs/)
[![GitHub issues](https://img.shields.io/github/issues/PerfectlySoft/Perfect.svg)](https://github.com/PerfectlySoft/Perfect/issues)
[![codebeat](https://codebeat.co/badges/85f8f628-6ce8-4818-867c-21b523484ee9)](https://codebeat.co/projects/github-com-perfectlysoft-perfect)
[![Twitter](https://img.shields.io/badge/Twitter-@PerfectlySoft-blue.svg?style=flat)](http://twitter.com/PerfectlySoft)
[![Join the chat at https://gitter.im/PerfectlySoft/Perfect](https://img.shields.io/badge/Gitter-Join%20Chat-brightgreen.svg)](https://gitter.im/PerfectlySoft/Perfect?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

**The master branch of this project currently compiles with the July 25th Swift toolchain.**

**Important:** On OS X you must set the Xcode command line tools preference as follows:
![Xcode Prefs](http://www.perfect.org/docs/assets/xcode_prefs.png) 

If you do not do this you will experience compile time errors when using SPM on the command line.

If you are still having build problems with any of the code in our repositories, try doing a clean build with Swift Package Manager by typing:

```swift build --clean=dist ; swift build```

--

Perfect is an application server for Linux or OS X which provides a framework for developing web and other REST services in the Swift programming language. Its primary focus is on facilitating mobile apps which require backend server software, enabling you to use one language for both front and back ends.

Perfect operates using either its own stand-alone HTTP/HTTPS server or through FastCGI. It provides a system for loading your own Swift based modules at startup and for interfacing those modules with its request/response objects or to the built-in mustache template processing system.

Perfect is built on its own high performance completely asynchronous networking engine with the goal of providing a scalable option for internet services. It supports SSL out of the box and provides a suite of tools which are commonly required by internet servers, such as WebSockets and iOS push notifications, but does not limit your options. Feel free to swap in your own favorite JSON or templating systems, etc.

## Issues

We are transitioning to using JIRA for all bugs and support related issues, therefore the GitHub issues has been disabled.

If you find a mistake, bug, or any other helpful suggestion you'd like to make on the docs please head over to [http://jira.perfect.org:8080/servicedesk/customer/portal/1](http://jira.perfect.org:8080/servicedesk/customer/portal/1) and raise it.

A comprehensive list of open issues can be found at [http://jira.perfect.org:8080/projects/ISS/issues](http://jira.perfect.org:8080/projects/ISS/issues)

## Quick Start

### Swift 3.0

Ensure you have properly installed a Swift 3.0 toolchain from [Swift.org](https://swift.org/getting-started/). In the terminal, typing:

```
swift --version
```

should produce something like the following:

```
Apple Swift version 3.0-dev (LLVM 440a472499, Clang e10506ae1c, Swift 395e967875)
Target: x86_64-apple-macosx10.9
```

### OS X
Perfect relies on [Home Brew](http://brew.sh) for installing dependencies on OS X. This is currently limited to OpenSSL. To install Home Brew, in the Terminal, type:

```
/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
```

To install OpenSSL:

```
brew install openssl
brew link openssl --force
```

### Linux
Perfect relies on OpenSSL, libssl-dev and uuid:

```
sudo apt-get install openssl libssl-dev uuid-dev
```

### Build Starter Project

The following will clone and build an empty starter project and launch the server on port 8181.

```
git clone https://github.com/PerfectlySoft/PerfectTemplate.git
cd PerfectTemplate
swift build
.build/debug/PerfectTemplate
```

You should see the following output:

```
Starting HTTP server on 0.0.0.0:8181 with document root ./webroot
```

This means the server is running and waiting for connections. Access [http://localhost:8181/](http://127.0.0.1:8181/) to see the greeting. Hit control-c to terminate the server.

You can view the full source code for [PerfectTemplate](https://github.com/PerfectlySoft/PerfectTemplate). 

### Xcode

Swift Package Manager can generate an Xcode project which can run the PerfectTemplate server and provide full source code editing and debugging for your project. Enter the following in your terminal:

```
swift package generate-xcodeproj
```

Open the generated file "PerfectTemplate.xcodeproj". Ensure that you have selected the executable target and selected it to run on "My Mac". You can now run and debug the server.

## Next Steps

These example snippets show how to accomplish several common tasks that one might need to do when developing a Web/REST application. In all cases, the ```request``` and ```response``` variables refer, respectively, to the ```HTTPRequest``` and ```HTTPResponse``` objects which are given to your URL handlers.

Consult the [API reference](http://www.perfect.org/docs/) for more details.

### Get a client request header

```swift
if let acceptEncoding = request.header(.acceptEncoding) {
	...
}
```

### Get client GET or POST parameters

```swift
if let foo = request.param(name: "foo") {
	...
}   
if let foo = request.param(name: "foo", defaultValue: "default foo") {
	...
}
let foos: [String] = request.params(named: "foo")
```

### Get the current request path

```swift
let path = request.path
```

### Access the server's document directory and return an image file to the client

```swift
let docRoot = request.documentRoot
do {
    let mrPebbles = File("\(docRoot)/mr_pebbles.jpg")
    let imageSize = mrPebbles.size
    let imageBytes = try mrPebbles.readSomeBytes(count: imageSize)
    response.setHeader(.contentType, value: MimeType.forExtension("jpg"))
    response.setHeader(.contentLength, value: "\(imageBytes.count)")
    response.setBody(bytes: imageBytes)
} catch {
    response.status = .internalServerError
    response.setBody(string: "Error handling request: \(error)")
}
response.completed()
```

### Get client cookies

```swift
for (cookieName, cookieValue) in request.cookies {
	...
}
```

### Set client cookie

```swift
let cookie = HTTPCookie(name: "cookie-name", value: "the value", domain: nil,
                    expires: .session, path: "/",
                    secure: false, httpOnly: false)
response.addCookie(cookie)
```

### Return JSON data to client

```swift
response.setHeader(.contentType, value: "application/json")
let d: [String:Any] = ["a":1, "b":0.1, "c": true, "d":[2, 4, 5, 7, 8]]
    
do {
    try response.setBody(json: d)
} catch {
    //...
}
response.completed()
```
*This snippet uses the built-in JSON encoding. Feel free to bring in your own favorite JSON encoder/decoder.*

### Redirect the client

```swift
response.status = .movedPermanently
response.setHeader(.location, value: "http://www.perfect.org/")
response.completed()
```

### Filter and handle 404 errors in a custom manner

```swift
struct Filter404: HTTPResponseFilter {
	func filterBody(response: HTTPResponse, callback: (HTTPResponseFilterResult) -> ()) {
		callback(.continue)
	}
	
	func filterHeaders(response: HTTPResponse, callback: (HTTPResponseFilterResult) -> ()) {
		if case .notFound = response.status {
			response.bodyBytes.removeAll()
			response.setBody(string: "The file \(response.request.path) was not found.")
			response.setHeader(.contentLength, value: "\(response.bodyBytes.count)")
			callback(.done)
		} else {
			callback(.continue)
		}
	}
}

let server = HTTPServer()
server.setResponseFilters([(Filter404(), .high)])
server.serverPort = 8181
try server.start()
```

## Repository Layout

We have finished refactoring Perfect to support Swift Package Manager. The Perfect project has been split up into the following repositories:

* [Perfect](https://github.com/PerfectlySoft/Perfect) - This repository contains the core PerfectLib and will continue to be the main landing point for the project.
* [PerfectTemplate](https://github.com/PerfectlySoft/PerfectTemplate) - A simple starter project which compiles with SPM into a stand-alone executable HTTP server. This repository is ideal for starting on your own Perfect based project.
* [PerfectDocs](https://github.com/PerfectlySoft/PerfectDocs) - Contains all API reference related material.
* [PerfectExamples](https://github.com/PerfectlySoft/PerfectExamples) - All the Perfect example projects and documentation.
* [Perfect-Mustache](https://github.com/PerfectlySoft/Perfect-Mustache) - Mustache template processor.
* [Perfect-Notifications](https://github.com/PerfectlySoft/Perfect-Notifications) - iOS Notifications (APNS) Support.
* [PerfectTemplateFCGI](https://github.com/PerfectlySoft/PerfectTemplateFCGI) - A simple starter project which compiles with SPM into a FastCGI server suitable for use with Apache 2.4 or NGINX. This repository is ideal for starting on your own Perfect based project if you are required to use an existing server which supports FastCGI.
* [Perfect-Redis](https://github.com/PerfectlySoft/Perfect-Redis) - Redis database connector.
* [Perfect-SQLite](https://github.com/PerfectlySoft/Perfect-SQLite) - SQLite3 database connector.
* [Perfect-PostgreSQL](https://github.com/PerfectlySoft/Perfect-PostgreSQL) - PostgreSQL database connector.
* [Perfect-MySQL](https://github.com/PerfectlySoft/Perfect-MySQL) - MySQL database connector.
* [Perfect-MongoDB](https://github.com/PerfectlySoft/Perfect-MongoDB) - MongoDB database connector.
* [Perfect-FastCGI-Apache2.4](https://github.com/PerfectlySoft/Perfect-FastCGI-Apache2.4) - Apache 2.4 FastCGI module; required for the Perfect FastCGI server variant.

The database connectors are all stand-alone and can be used outside of the Perfect framework and server.

## Further Information
For more information on the Perfect project, please visit [perfect.org](http://perfect.org).
