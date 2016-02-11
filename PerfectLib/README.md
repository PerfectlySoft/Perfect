# PerfectLib
![Perfect logo](http://www.perfect.org/images/icon_128x128.png)

PerfectLib is a Swift module providing a set of core utilities for both server and client development. In many cases the same APIs are utilized on both the client and the server. However, the goal is to leaverage the APIs provided by the platform on the client side, reducing the potential for bloat, while providing a complete server-side solution supporting both Linux and OS X. The aim is to permit the same domain model code to be used by both client and server while providing the minimum functionality required to support communication and synchronization between the two sides.

The client-side module aims to be light weight, providing support for the following:

* Raw byte stream management
* Simplified UTF-8/16 encoding and decoding
* Unicode related utilities for character testing
* UUID creation and conversion to and from String
* cURL support
* Simplified SQLite access
* JSON encoding and decoding
* JSON based object marshalling to and from the server-side

The server-side module provides a complete set of tools for server development. It is designed to operate on both Linux and OS X using a unified set of APIs. PerfectLib includes support for:

* Raw byte stream management
* Simplified UTF-8/16 encoding and decoding
* UUID creation and conversion to and from String
* cURL support
* TCP and UNIX socket networking
* LibEvent integration for high performance scalable networking
* ICU integration for full Unicode support, including character conversion and date/time parsing and formatting
* File and directory objects
* Process management, including launching, terminating and IPC
* FastCGI based application serving
* HTTP (stand-alone) based application serving
* Web request and response APIs, abstracted to operate over either FastCGI or stand-alone HTTP
* Multi-part POST/MIME parsing and file upload handling
* Dynamic module loading for server extensions
* Mustache template parsing and processing
* A web request handler system for associating Swift classes with mustache templates
* Server-side state/session management
* Database connectors for MySQL, PostgreSQL, SQLite and MongoDB
* JSON encoding and decoding
* JSON based object marshalling to and from the client-side

## Linux Build Notes
PerfectLib builds on Ubuntu with the provided makefile. You must have a working [Swift compiler for Linux](https://swift.org/download/#linux). The swift compiler must be available through your $PATH. You will also need to ensure you have the following dependencies installed through apt-get:

* libssl-dev
* libevent-dev
* libsqlite3-dev
* libcurl4-openssl-dev
* libicu-dev
* uuid-dev

After cloning the repository *git clone https://github.com/PerfectlySoft/Perfect.git*, execute the following commands:

* cd Perfect/PerfectLib
* make
* sudo make install

The final step will place symlinks into /usr/local/lib

Executing `ls /usr/local/lib/*Perfect*` should report:

/usr/local/lib/PerfectLib.so  /usr/local/lib/PerfectLib.swiftdoc  /usr/local/lib/PerfectLib.swiftmodule

You can now proceed to build [Perfect Server](../PerfectServer/#perfectserver) and then the [Examples](../Examples/#examples).
