# Perfect Examples
![Perfect logo](../PerfectServer/PerfectServerHTTPApp/Assets.xcassets/AppIcon.appiconset/icon_128x128.png)
## Getting Started
After cloning the repository or downloading and expanding the zip file, navigate to the Examples directory and open the Examples.xcworkspace file. Each of the example projects consist of a target for an iOS mobile app and a corresponding server module. Each server module is associated with the **Perfect Server HTTP App** permitting it to be launched directly from within Xcode. By default, the server will listen on localhost on port **8181** and each example iOS app will attempt to contact the local server on that port. If you need to change this port, it can be done in the settings for the HTTP App and in the source code for each iOS app.

Perfect Server HTTP Settings:

![Dev HTTP Window](../SiteAssets/perfect_dev_http_window.png)

Example end point in source code:

![Dev HTTP Window](../SiteAssets/end_point_edit.png)

## Example Apps
### Tap Tracker

![Example Targets](../SiteAssets/example_targets.png)

The simplest example app is called Tap Tracker. The Tap Tracker iOS app presents a button to the user. When tapped, this button will transmit the user's current location to the server. The server will store this location and will return to the iOS app the location of the last user who tapped the button. The app will then show this location on a map view.

To execute this example from within Xcode, run the **Tap Tracker Server** target and then the **Tap Tracker** target using an iPhone device simulator of your choice. Ensure that both targets are running simultaniously and that the **Tap Tracker** iOS app is set to simulate your location. 

![Simulate Location](../SiteAssets/simulate_location.png)

Additionally, make sure to choose "Allow" when the app requests that you permit it to use your location.

#### Client Operations
1. `ViewController` starts location services and records the user's current location.
2. `ViewController` presents a single button for the user to tap.
3. When user taps the button the `buttonPressed` function is called.
4. `buttonPressed` formulates an HTTP POST request using standard iOS `NSMutableURLRequest` and `NSURLSession` functionality. This post request is very simple and consists merely of the user's latitude and longitude.
5. `ViewController` receives the JSON structured response data from the server and uses Perfect's `JSONDecode` class to break the data apart and extract the location and time information pertaining to the previous button tap.
6. The response's `lat`, `long` and `time` components are used to indicate the map location on the subsequent map view.

#### Server Operations
1. Stuff
2. More



