# Perfect Installer

The Perfect Installer is a bash script named perfectinstaller that will prep a new or existing Ubuntu system with neccessary dependencies to install, run, and execute both Swift and Perfect. 

## How to Install Perfect and Run

To install Swift and Perfect, run this command from within the Perfect directory:
```sh
$ ./perfectinstaller
```
The script will always try to get the most updated dependencies, such as: 
- libicu-dev
- libssl-dev
- libevent-dev
- libsqlite3-dev

It will then attempt download, verify, and install Swift version "swift-2.2-SNAPSHOT-2016-01-11-a" if the folder is not found. Currently, you will have to run the script twice on the initial installation. The script does not currently update your PATH variables. A handy print out is supplied at the end of the script. 
The suggested solution is to use either the **/etc/profile.d/** or **/etc/environment/** option. 

For fast installation do the following:
```sh 
$ echo "export PATH=$PATH:$HOME/Swift_Snapshots/swift-2.2-SNAPSHOT-2016-01-11-a-ubuntu15.10/usr/bin" >> ~/.bash_profile
$ source ~/.bash_profile
$ ./perfectinstaller
```

Lastly, the script also make a folder at **${HOME}/SwiftServer/PerfectLibraries**. You should create an additional folder **${HOME}/SwiftServer/webroot** and add a default index.html. Running **perfectserverhttp** will create the folder for you, but the server will not have anything to server and you will have to restart with an index.html later. So might as well do it now. 

## Running Examples 
Navigate to the example folder - **/Perfect/Examples/**. You can either build all the examples by running the following command here, or one individuallly by navigating into the folder like so:

**Build All Examples**
```sh 
$ cd /Perfect/Examples
$ make 
```
**Build Specfic Example** 
```sh
$ cd /Tap\ Tracker
$ make 
```
With everything built, you need to copy the TapTracker.so file to **${HOME}/SwiftServer/PerfectLibraries**, the index.html(if you didn't before), and TapTracker.mustache to **${HOME}/SwiftServer/webroot**

Now, wherever you run **perfectserverhttp** from is the folder its going to make/look for the webroot folder. So be sure to run **perfectserverhttp** from within **${HOME}/SwiftServer/** like so:
```sh 
$ cd $HOME/SwiftServer
$ ./perfectserverhttp
```
Given there aren't any errors in the terminal, go to the url it's listing like 0.0.0.0:8181 to see a hello world message or 0.0.0.0:8181/TapTracker to see a JSON response!
