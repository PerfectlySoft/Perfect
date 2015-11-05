# Perfect Server
![Perfect logo](http://www.perfect.org/images/icon_128x128.png)

**Perfect Server** is the server-side component that makes Perfect tick. It is a stand-alone process which stays running and accepts connections from clients, processing requests and returning responses. It has a plugin mechanism for allowing developers to include their application logic modules, known as handlers, into the system. These handlers are associated with moustache templates which provide the response formatting mechanism. This methodology provides a clean separation of logic and presentation following the classic MVC architecture.

## Flavors

**Perfect Server** comes in two flavors; a FastCGI based version which ties into Apache 2.4 through [mod_perfect](../Connectors/mod_perfect/#mod_perfect), and a stand-alone HTTP server variant. The stand-alone HTTP version also includes a native OS X app which makes it very easy to start and configure a new instance. Any variant can be easily launched through Xcode permitting simultanious debugging of the client and the server.
![Dev HTTP Window](../SiteAssets/perfect_dev_http_window.png)

Both server variants are implimented as their own classes, making it very easy to embed the servers in your own main Swift processes, or you can use the provided projects which generate Swift based executables.

![Perfect Server Targets](../SiteAssets/perfect_server_targets.png)

## Operations
When **Perfect Server** launches, it looks for various resources in particularly named directories located in the processes' current working directory. These directories are as follows:

* *PerfectLibraries* - This directory contains all the developer created handler modules. At startup, the server will dynamically load these modules and attempt to call a function within each named `PerfectServerModuleInit`. Within this function all handlers should be registered. Check the [Examples](../Examples/#examples) for a walkthrough on how this system operates.
* *SQLiteDBs* - Some facilities provided by Perfect Server utilize a local SQLite database for storage of temporary or configuration data (for example, the Sessions feature). This directory will be created automatically if it does not exist and any required databases will be generated as required.
* *webroot* - This directory is needed by the stand-alone HTTP server variant. Within this directory all web content will be sought. This includes any regular static content such as HTML or images, and any moustache templates.

### FastCGI
Write me.

### HTTP
Write me.
