# Perfect: Server-Side Swift
![Perfect logo](https://www.perfect.org/images/icon_128x128.png)

[![Swift 2.2](https://img.shields.io/badge/Swift-2.2-orange.svg?style=flat)](https://developer.apple.com/swift/)
[![Platforms OS X | iOS | Linux](https://img.shields.io/badge/Platforms-OS%20X%20%7C%20iOS%20%7C%20Linux%20-lightgray.svg?style=flat)](https://developer.apple.com/swift/)
[![License Apache](https://img.shields.io/badge/License-Apache-lightgrey.svg?style=flat)](http://perfect.org/licensing.html)
[![Docs](https://img.shields.io/badge/docs-83%-yellow.svg?style=flat)](http://www.perfect.org/docs/)
[![Issues](https://img.shields.io/github/release/qubyte/rubidium.svg)](https://github.com/PerfectlySoft/Perfect/issues)
[![Donate](https://img.shields.io/badge/Donate-PayPal-blue.svg?style=flat)](https://paypal.me/perfectlysoft)
[![Twitter](https://img.shields.io/badge/Twitter-@PerfectlySoft-brightgreen.svg?style=flat)](http://twitter.com/PerfectlySoft)
[![Join the chat at https://gitter.im/PerfectlySoft/Perfect](https://img.shields.io/badge/Gitter-Join%20Chat-brightgreen.svg)](https://gitter.im/PerfectlySoft/Perfect?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

Perfect is an application server for Linux or OS X which provides a framework for developing web and other REST services in the Swift programming language. Its primary focus is on facilitating mobile apps which require backend server software, enabling you to use one language for both front and back ends.

Perfect operates using either its own stand-alone HTTP server or through FastCGI but is flexible enough to be attached to the server of your choice or to your own custom server. It provides a system for loading your own Swift based modules at startup and for interfacing those modules with its request/response objects or to the built-in mustache template processing system.

Perfect is built on its own high performance completely asynchronous networking engine with the goal of providing a scalable option for internet services. It supports SSL out of the box and provides a suite of tools which are commonly required by internet servers, such as WebSockets and iOS push notifications, but does not limit your options. Feel free to swap in your own favorite JSON or templating systems, etc.

**Please Note**
[v1.0 has been released](https://github.com/PerfectlySoft/Perfect/releases/tag/v1.0.0). For a stable development environment, switch to branch **release-1.0** or download [v1.0](https://github.com/PerfectlySoft/Perfect/releases/tag/v1.0.0). **v1.0 requires the Swift 2.2 toolchain.**

(2016-04-18) We have finished the main refactoring tasks required to support Swift Package Manager. The Perfect project has been split up into the following repositories:

* [Perfect](https://github.com/PerfectlySoft/Perfect) - This repository contains the core PerfectLib and will continue to be the main landing point for the project.
* [PerfectServer](https://github.com/PerfectlySoft/PerfectServer) - Contains the PerfectServer variants, including the stand-alone HTTP and FastCGI servers. Those wishing to do a manual deployment should clone and build from this repository.
* [PerfectStarter](https://github.com/PerfectlySoft/PerfectStarter) - This umbrella repository allows one to pull in all the related Perfect modules in one go, including the servers, examples, database connectors and documentation. This is a great place to start for people wishing to get up to speed with Perfect.
* [PerfectDocs](https://github.com/PerfectlySoft/PerfectDocs) - Contains all API reference related material.
* [PerfectExamples](https://github.com/PerfectlySoft/PerfectExamples) - All the Perfect example projects and documentation.
* [Perfect-FastCGI-Apache2.4](https://github.com/PerfectlySoft/Perfect-FastCGI-Apache2.4) - Apache 2.4 FastCGI module; required for the Perfect FastCGI server variant.
* [Perfect-SQLite](https://github.com/PerfectlySoft/Perfect-SQLite) - SQLite3 database connector.
* [Perfect-PostgreSQL](https://github.com/PerfectlySoft/Perfect-PostgreSQL) - PostgreSQL database connector.
* [Perfect-MySQL](https://github.com/PerfectlySoft/Perfect-MySQL) - MySQL database connector.
* [Perfect-MongoDB](https://github.com/PerfectlySoft/Perfect-MongoDB) - MongoDB database connector.

The database connectors are all stand-alone and can be used outside of the Perfect framework and server.

Note that we are still making some tweaks to this layout and are currently ensuring that everything builds properly on Linux and OS X using SPM and Xcode. This new code **requires** a Swift 3.0 toolchain and is currently being built against the *April 12, 2016* snapshot. It will **not** compile with Swift 2.2.

(2016-04-05) We are **refactoring** the Perfect project repository with the ultimate goal of supporting the Swift Package Manager. The various modules, such as the PerfectLib, server, database connectors and examples pack are being split off into their own repositories. This change will also include some API streamlining and fewer 3rd party dependencies resulting in easier installation and deployment. Once this task has completed we will release as v1.1 and continue from there. We hope to have these changes solidified by the end of the week and we appreciate all the feedback we've received along the way. 

If you've been working on a Perfect project switch to branch **release-1.0** to maintain the stable API you've been developing against.

## More Information
For more information on the Perfect project, please visit [perfect.org](http://perfect.org).
