#!/bin/bash
swift package generate-xcodeproj && xcodebuild test -project PerfectClassic.xcodeproj/ -scheme PerfectClassic-Package