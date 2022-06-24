#!/bin/bash
cp smtp.test.json /tmp/ && \
swift package generate-xcodeproj && xcodebuild test -project Perfect.xcodeproj/ -scheme Perfect-Package
