# Perfect Examples
![Perfect logo](https://www.perfect.org/images/icon_128x128.png)

These examples illustrate how Xcode projects which use Perfect are organized and how the clients and servers are run and debugged. Each example aims to show a different aspect of how Perfect operates with the goal of getting developers up to speed and creating their own server solutions.

* [Getting Started](#getting-started)
* [URL Routing](URL%20Routing/#url-routing)
* [WebSockets](WebSockets%20Server/#websockets-server)
* [Tap Tracker](Tap%20Tracker/#tap-tracker)
* [Upload Enumerator](Upload%20Enumerator/#upload-enumerator)
* [Authenticator](Authenticator/#authenticator)

## Getting Started
After cloning the repository or downloading and expanding the zip file, navigate to the Examples directory and open the Examples.xcworkspace file. Each of the example projects consist of a target for an iOS mobile app and a corresponding server module. Each server module is associated with the **Perfect Server HTTP App** permitting it to be launched directly from within Xcode. By default, the server will listen on localhost on port **8181** and each example iOS app will attempt to contact the local server on that port. If you need to change this port, it can be done in the settings for the HTTP App and in the source code for each iOS app.

Perfect Server HTTP Settings:

![Dev HTTP Window](../SiteAssets/perfect_dev_http_window.png)

Example end point in source code:

![End Point Edit](../SiteAssets/end_point_edit.png)

## Linux Build Notes
First, ensure you have built [PerfectLib](../PerfectLib/#perfectlib) and [Perfect Server](../PerfectServer/#perfectserver).

* cd into the desired example directory
* make
* This will produce a .so library which should be copied or linked into the PerfectLibraries directory in whatever location you are running the Perfect Server from.

## Example Apps
* [URL Routing](URL%20Routing/#url-routing)
* [WebSockets](WebSockets%20Server/#websockets-server)
* [Tap Tracker](Tap%20Tracker/#tap-tracker)
* [Upload Enumerator](Upload%20Enumerator/#upload-enumerator)
* [Authenticator](Authenticator/#authenticator)
