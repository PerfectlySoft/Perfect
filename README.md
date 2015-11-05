# Perfect
![Perfect logo](http://www.perfect.org/images/icon_128x128.png)

Perfect is a framework for developing web and other REST services in the Swift programming language. Its primary focus is on facilitating mobile apps which require backend server software. It permits you to use one language for both front and back ends.

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
	* Mobile iOS Examples
	* Web Site Examples
	* Game Examples (coming soon!)

## Getting Started
Check the [README](Examples/#examples) in the Examples directory for further instructions.

