# URL Routing
This example illustrates how to set up URL routing to direct requests to your custom handlers.

## Enabling URL Routing

In your `PerfectServerModuleInit` function, which all Perfect modules must have, enable URL routing by calling `Routing.Handler.registerGlobally()`. Then add one or more URL routes using the `Routing.Routes` subscript functions.

The following code is taken from the example project and shows how to enable the system and add routes.

```
public func PerfectServerModuleInit() {
	
	// Install the built-in routing handler.
	// Using this system is optional and you could install your own system if desired.
	Routing.Handler.registerGlobally()
	
	Routing.Routes["GET", ["/", "index.html"] ] = { (_:WebResponse) in return IndexHandler() }
	Routing.Routes["/foo/*/baz"] = { _ in return EchoHandler() }
	Routing.Routes["/foo/bar/baz"] = { _ in return EchoHandler() }
	Routing.Routes["GET", "/user/{id}/baz"] = { _ in return Echo2Handler() }
	Routing.Routes["POST", "/user/{id}/baz"] = { _ in return Echo3Handler() }
	
	// Check the console to see the logical structure of what was installed.
	print("\(Routing.Routes.description)")
}
```
## Handling Requests

The example `EchoHandler` consists of the following.

```
class EchoHandler: RequestHandler {
	
	func handleRequest(request: WebRequest, response: WebResponse) {
		response.appendBodyString("Echo handler: You accessed path \(request.requestURI()) with variables \(request.urlVariables)")
		response.requestCompletedCallback()
	}
}
```

## Using Apache
The following Apache conf snippet can be used to pipe requests for non-existent files through to Perfect when using the URL routing system.

```
	RewriteEngine on
	RewriteCond %{REQUEST_FILENAME} !-f
	RewriteCond %{REQUEST_FILENAME} !-d
	RewriteRule (.*) - [L,NS,H=perfect-handler]
```
