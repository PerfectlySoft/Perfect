# Perfect 
![Perfect logo](http://perfect.org/images/perfect-git-banner.jpg) 

[![Swift 2.2](https://img.shields.io/badge/Swift-2.2-orange.svg?style=flat)](https://developer.apple.com/swift/)
[![Platforms OS X | iOS | Linux](https://img.shields.io/badge/Platforms-OS%20X%20%7C%20iOS%20%7C%20Linux%20-lightgray.svg?style=flat)](https://developer.apple.com/swift/)
[![License Apache](https://img.shields.io/badge/License-Apache-lightgrey.svg?style=flat)](http://perfect.org/licensing.html)
[![Docs](https://img.shields.io/badge/docs-83%-yellow.svg?style=flat)](http://www.perfect.org/docs/)
[![Issues](https://img.shields.io/github/release/qubyte/rubidium.svg)](https://github.com/PerfectlySoft/Perfect/issues)
[![Donate](https://img.shields.io/badge/Donate-PayPal-blue.svg?style=flat)](https://paypal.me/perfectlysoft)
[![Twitter](https://img.shields.io/badge/Twitter-@PerfectlySoft-brightgreen.svg?style=flat)](http://twitter.com/PerfectlySoft)
[![Join the chat at https://gitter.im/PerfectlySoft/Perfect](https://img.shields.io/badge/Gitter-Join%20Chat-brightgreen.svg)](https://gitter.im/PerfectlySoft/Perfect?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

**Please Note**
[v1.0 has been released](https://github.com/PerfectlySoft/Perfect/releases/tag/v1.0.0)

For a stable development environment, switch to branch **release-1.0** or download [v1.0](https://github.com/PerfectlySoft/Perfect/releases/tag/v1.0.0)

(2016-04-05) We are **refactoring** the Perfect project repository with the ultimate goal of supporting the Swift Package Manager. The various modules, such as the PerfectLib, server, database connectors and examples pack are being split off into their own repositories. This change will also include some API streamlining and fewer 3rd party dependencies resulting in easier installation and deployment. Once this task has completed we will release as v1.1 and continue from there. We hope to have these changes solidified by the end of the week and we appreciate all the feedback we've received along the way. 

If you've been working on a Perfect project switch to branch **release-1.0** to maintain the stable API you've been working with.

**WebSockets & iOS Push Notifications**

Perfect now includes a **WebSockets** server and support for handling your own server-side **iOS push notifications**.

**Perfect now runs on Linux!**

Perfect now builds and runs on Linux with the [open source release of Swift](https://github.com/apple/swift). Consult the readmes of the individual components for build instructions.

Perfect is an application server which provides a framework for developing web and other REST services in the Swift programming language. Its primary focus is on facilitating mobile apps which require backend server software. It enables you to use one language for both front and back ends.

Perfect operates using either its own stand-alone HTTP server or through FastCGI with Apache 2.4. It provides a system for loading your own Swift based modules at startup and for interfacing those modules with its built-in request/response objects or the mustache template processing system.

Perfect consists of the following components:

* [PerfectLib](PerfectLib/#perfectlib) - Framework components and utilities for client and server.
	* [PerfectLib Reference](http://www.perfect.org/docs/)
	* OS X / Linux
	* iOS
* [Perfect Server](PerfectServer/#perfectserver) - Backend server supporting FastCGI or stand-alone HTTP.
	* Perfect Server FastCGI - Server process which accepts connections over FastCGI.
	* Perfect Server HTTP - Stand-alone HTTP server.
	* Perfect Server HTTP App - Development focused stand-alone HTTP server OS X app.
* Connectors - Server-side connectivity.
	* [mod_perfect](Connectors/mod_perfect/#mod_perfect) - FastCGI connectivity for Apache 2.4.
	* [MySQL](Connectors/MySQL/#mysql) - Provides connectivity for MySQL databases.
	* [PostgreSQL](Connectors/PostgreSQL/#postgresql) - Provides connectivity for PostgreSQL databases.
	* [MongoDB](Connectors/MongoDB/#mongodb) - Provides connectivity for MongoDB databases.
* [Examples](Examples/#examples) - A set of examples which show how to utilize Perfect.
	* Mobile iOS Examples
	* Web Site Examples
	* Game Examples (coming soon!)

## Getting Started
Check the [README](Examples/#examples) in the Examples directory for further instructions.

## More Information
For more information on the Perfect project, please visit [perfect.org](http://perfect.org).
