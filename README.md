# Perfect
![Perfect logo](PerfectServer/PerfectServerHTTPApp/Assets.xcassets/AppIcon.appiconset/icon_128x128.png)

Perfect is framework for developing web and other REST services in the Swift programming language. It's primary focus is on facilitating mobile apps which require backend server software. It permits you to use one language for both front and back ends.

It consists of the following components:

* [PerfectLib](PerfectLib/#perfectlib) - Framework components and utilities for client and server.
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

## Getting Started
After cloning the repository or downloading and expanding the zip file, navigate to the Examples directory and open the Examples.xcworkspace file. Each of the example projects consist of a target for an iOS mobile app and a corresponding server module. Each server module is associated with the **Perfect Server HTTP App** permitting it to be launched directly from within Xcode. By default, the server will listen on localhost on port **8181** and each example iOS app will attempt to contact the local server on that port. If you need to change this port, it can be done in the settings for the HTTP App and in the source code for each iOS app.

Check the [README](Examples/#examples) in the Examples directory for further instructions.

