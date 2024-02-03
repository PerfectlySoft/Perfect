#!/bin/bash
cp smtp.test.json /tmp/ && \
swift test --filter PerfectSMTPTests --filter PerfectSQLiteTests --filter PerfectHTTPTests && \
swift test --skip PerfectSMTPTests --skip PerfectSQLiteTests --skip PerfectHTTPTests

