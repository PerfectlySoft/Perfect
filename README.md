# Perfect: Server-Side Swift
[![Perfect logo](http://www.perfect.org/images/perfect-git-banner.png)](http://perfect.org/get-involved.html)

[![Swift 3.0](https://img.shields.io/badge/Swift-3.0-orange.svg?style=flat)](https://developer.apple.com/swift/)
[![Platforms OS X | Linux](https://img.shields.io/badge/Platforms-OS%20X%20%7C%20Linux%20-lightgray.svg?style=flat)](https://developer.apple.com/swift/)
[![License Apache](https://img.shields.io/badge/License-Apache-lightgrey.svg?style=flat)](http://perfect.org/licensing.html)
[![Docs](https://img.shields.io/badge/docs-99%25-yellow.svg?style=flat)](http://www.perfect.org/docs/)
[![Issues](https://img.shields.io/github/release/qubyte/rubidium.svg)](https://github.com/PerfectlySoft/Perfect/issues)
[![Donate](https://img.shields.io/badge/Donate-PayPal-blue.svg?style=flat)](https://paypal.me/perfectlysoft)
[![Twitter](https://img.shields.io/badge/Twitter-@PerfectlySoft-brightgreen.svg?style=flat)](http://twitter.com/PerfectlySoft)
[![Join the chat at https://gitter.im/PerfectlySoft/Perfect](https://img.shields.io/badge/Gitter-Join%20Chat-brightgreen.svg)](https://gitter.im/PerfectlySoft/Perfect?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

**The master branch of this project currently compiles with *Swift 3.0 Preview 1* released June 13, 2016 using Swift Package Manager.**

**Important:** On OS X you must set the Xcode command line tools preference as follows:
![Xcode Prefs](assets/xcode_prefs.png) 

If you do not do this you will experience compile time errors when using SPM on the command line.

--

Perfect is an application server for Linux or OS X which provides a framework for developing web and other REST services in the Swift programming language. Its primary focus is on facilitating mobile apps which require backend server software, enabling you to use one language for both front and back ends.

Perfect operates using either its own stand-alone HTTP/HTTPS server or through FastCGI. It provides a system for loading your own Swift based modules at startup and for interfacing those modules with its request/response objects or to the built-in mustache template processing system.

Perfect is built on its own high performance completely asynchronous networking engine with the goal of providing a scalable option for internet services. It supports SSL out of the box and provides a suite of tools which are commonly required by internet servers, such as WebSockets and iOS push notifications, but does not limit your options. Feel free to swap in your own favorite JSON or templating systems, etc.

## Quick Start

### Swift 3.0

Ensure you have properly installed a Swift 3.0 toolchain from [Swift.org](https://swift.org/getting-started/). In the terminal, typing:

```
swift --version
```

should produce something like the following:

```
Apple Swift version 3.0 (swiftlang-800.0.30 clang-800.0.24)
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
Perfect relies on OpenSSL and uuid:

```
sudo apt-get install openssl uuid-dev
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

These example snippets show how to accomplish several common tasks that one might need to do when developing a Web/REST application. In all cases, the ```request``` and ```response``` variables refer, respectively, to the ```WebRequest``` and ```WebResponse``` objects which are given to your URL handlers.

Consult the [API reference](http://www.perfect.org/docs/) for more details.

### Get a client request header

```swift
if let acceptEncoding = request.header(named: "Accept-Encoding") {
	...
}
// Many common HTTP request headers have their own accessors
if let acceptEncoding2 = request.httpAcceptEncoding {
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

### Get the current request URI

```swift
if let uri = request.requestURI {
	...        
}
```

### Access the server's document directory and return an image file to the client

```swift
let docRoot = request.documentRoot
do {
    let mrPebbles = File("\(docRoot)/mr_pebbles.jpg")
    let imageSize = mrPebbles.size
    let imageBytes = try mrPebbles.readSomeBytes(count: imageSize)
    response.replaceHeader(name: "Content-Type", value: MimeType.forExtension("jpg"))
    response.replaceHeader(name: "Content-Length", value: "\(imageBytes.count)")
    response.appendBody(bytes: imageBytes)
} catch {
    response.setStatus(code: 500, message: "Internal Server Error")
    response.appendBody(string: "Error handling request: \(error)")
}
response.requestCompleted()
```

### Get client cookies

```swift
for (cookieName, cookieValue) in request.cookies {
	...
}
```

### Set client cookie

```swift
let cookie = Cookie(name: "cookie-name", value: "the value", domain: nil,
                    expires: .session, path: "/",
                    secure: false, httpOnly: false)
response.addCookie(cookie: cookie)
```

### Return JSON data to client

```swift
response.replaceHeader(name: "Content-Type", value: "application/json")
let dict: [String:Any] = ["a":1, "b":0.1, "c": true, "d":[2, 4, 5, 7, 8]]
    
do {
	let jsonString = try dict.jsonEncodedString()
	response.appendBody(string: jsonString)
} catch {
	...
}
response.requestCompleted()
```
*This snippet uses the built-in JSON encoding. Feel free to bring in your own favorite JSON encoder/decoder.*

## Repository Layout

We have finished refactoring Perfect to support Swift Package Manager. The Perfect project has been split up into the following repositories:

* [Perfect](https://github.com/PerfectlySoft/Perfect) - This repository contains the core PerfectLib and will continue to be the main landing point for the project.
* [PerfectTemplate](https://github.com/PerfectlySoft/PerfectTemplate) - A simple starter project which compiles with SPM into a stand-alone executable HTTP server. This repository is ideal for starting on your own Perfect based project.
* [PerfectDocs](https://github.com/PerfectlySoft/PerfectDocs) - Contains all API reference related material.
* [PerfectExamples](https://github.com/PerfectlySoft/PerfectExamples) - All the Perfect example projects and documentation.
* [PerfectEverything](https://github.com/PerfectlySoft/PerfectEverything) - This umbrella repository allows one to pull in all the related Perfect modules in one go, including the servers, examples, database connectors and documentation. This is a great place to start for people wishing to get up to speed with Perfect.
* [PerfectServer](https://github.com/PerfectlySoft/PerfectServer) - Contains the PerfectServer variants, including the stand-alone HTTP and FastCGI servers. Those wishing to do a manual deployment should clone and build from this repository.
* [Perfect-Redis](https://github.com/PerfectlySoft/Perfect-Redis) - Redis database connector.
* [Perfect-SQLite](https://github.com/PerfectlySoft/Perfect-SQLite) - SQLite3 database connector.
* [Perfect-PostgreSQL](https://github.com/PerfectlySoft/Perfect-PostgreSQL) - PostgreSQL database connector.
* [Perfect-MySQL](https://github.com/PerfectlySoft/Perfect-MySQL) - MySQL database connector.
* [Perfect-MongoDB](https://github.com/PerfectlySoft/Perfect-MongoDB) - MongoDB database connector.
* [Perfect-FastCGI-Apache2.4](https://github.com/PerfectlySoft/Perfect-FastCGI-Apache2.4) - Apache 2.4 FastCGI module; required for the Perfect FastCGI server variant.

The database connectors are all stand-alone and can be used outside of the Perfect framework and server.

## Further Information
For more information on the Perfect project, please visit [perfect.org](http://perfect.org).
