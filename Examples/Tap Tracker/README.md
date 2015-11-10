# Tap Tracker
The simplest example app is called Tap Tracker. The Tap Tracker iOS app presents a button to the user. When tapped, this button will transmit the user's current location to the server. The server will store this location and will return to the iOS app the location of the last user who tapped the button. The app will then show this location on a map view.

To execute this example from within Xcode, run the **Tap Tracker Server** target and then the **Tap Tracker** target using an iPhone device simulator of your choice. Ensure that both targets are running simultaniously and that the **Tap Tracker** iOS app is set to simulate your location. 

![Example Targets](../../SiteAssets/example_targets.png)

Additionally, make sure to choose "Allow" when the app requests that you permit it to use your location. If you receive an error stating that location services are not available, ensure that you have selected a location to simulate and restart the iOS Tap Tracker app.

![Simulate Location](../../SiteAssets/simulate_location.png)

## Client Operations
1. `ViewController` starts location services and records the user's current location.
2. `ViewController` presents a single button for the user to tap.
3. When user taps the button the `ViewController.buttonPressed` function is called.
4. `ViewController.buttonPressed` formulates an HTTP POST request to the URL *http://localhost:8181/TapTracker* using standard iOS `NSMutableURLRequest` and `NSURLSession` functionality. This post request is very simple and consists merely of the user's latitude and longitude.
5. `ViewController` receives the JSON structured response data from the server and uses Perfect's `JSONDecode` class to break the data apart and extract the location and time information pertaining to the previous button tap.
6. The response's `lat`, `long` and `time` components are used to indicate the map coordinates on the subsequent map view.

## Server Operations
1. The server module consists of two relevent files:
	* **TTHandlers.swift**, within which is the `PerfectServerModuleInit` function, which all Perfect Server modules must implement, and the `TTHandler` class, which implements the `PageHandler` protocol.
	* **TapTracker.moustache**, which contains the template for the JSON based response data.
2. When the **Tap Tracker Server** target is built in Xcode, it places the resulting product in a directory called **PerfectLibraries**. When the Perfect Server is launched, it will look in this directory, based on the current process working directory, and load all the modules it finds calling the `PerfectServerModuleInit` function in each.
3. `PerfectServerModuleInit` adds a page handler called "TTHandler", associating with it a closure which will be called to create an instance of the handler on-demand when it is needed to fulfill a request. This closure simply returns a new `TTHandler` instance.
4. In this example, the `PerfectServerModuleInit` function also creates a SQLite database for use in storing the button tap locations and times. It creates a very simple table storing the time, latitude and longitude of the users' button taps.
5. When a request comes in targetting the **/TapTracker** (or **/TapTracker.moustache**) URL, the server will parse the moustache file and run any moustache pragmas contained therein. This particular moustache template associates itself with the previously registered "TTHandler" by containing the following pragma at the beginning of the file: ```{{% handler:TTHandler}}```
6. The server will find "TTHandler" within its internal registry and instantiate the associated handler object; an instance of class `TTHandler`. (Note that the handler name and the class name do not have to match, although they do match for this particular example.)
7. The server calls the handler's `valuesForResponse` function, which is part of the `PageHandler` protocol, passing to it the request's `MoustacheEvaluationContext` and `MoustacheEvaluationOutputCollector` objects which contain all the information pertaining to the request. The return value of the `valuesForResponse` function is a Dictionary object populated with the keys and values used when processing the moustache template. The result of the template processing is the resulting data which will be sent back to the client.
8. The `TTHandler` handler searches in the SQLite database for the previous button tap data and, if available, will use it as the response to the client. If there are no existing tap data rows, the current tap location data will be returned.
9. The `TTHandler` handler pulls the POSTed `lat` and `long` values sent by the client and stores them, along with the current time, into the SQLite database.
10. Finally, the `TTHandler` handler uses the previously retrieved `lat`, `long` and `time` values to populate the Dictionary which will be used when completing the moustache template. It does this by storing the values into a Dictionary and storing that Dictionary into an Array which is then placed into the returned Dictionary under the "resultSets" key. This particular methodology of storing the results Dictionary into an Array is more convoluted than is required for this simple example, but it illustrates how a multi-row result would be returned to the moustache template. This is further explored in the following.

The content of the **TapTracker.moustache** file is as follows:

```
{{% handler:TTHandler}}{{!

	This is the moustache template file for the tap tracker example.
	
}}{"resultSets":[{{#resultSets}}{"time":"{{time}}","lat":{{lat}},"long":{{long}} }{{^last}},{{/last}}{{/resultSets}}]}
```

This template produces JSON data. The data is structured as an array of objects found under the "resultSets" key. Each object in the array has a "time", "lat" and "long" key. The final row (even though there is only one row in this example) in the array has a "last" key which permits the array of objects to be properly comma delimited whilst adhering to the "stateless" methodology of moustache templating.

Inside the handler, the data is placed into the resulting dictionary using the following code:

```
// The dictionary which we will return
var values = [String:Any]()
let timeStr = try ICU.formatDate(time, format: "yyyy-MM-d hh:mm aaa")
let resultSets: [[String:Any]] = [["time": timeStr, "lat":lat, "long":long, "last":true]]
values["resultSets"] = resultSets
return values
``` 

Above, one can see the server takes the raw time value and formats it as a string using the facilities provided by ICU. This, along with the lat and long values are placed in the dictionary which is used to complete the moustache template.