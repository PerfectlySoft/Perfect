#!/bin/bash
swift package generate-xcodeproj && xcodebuild test -project PerfectLib.xcodeproj/ -scheme PerfectLib-Package
