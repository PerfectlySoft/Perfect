#!/bin/bash
swift test --filter PerfectSMTPTests && \
swift test --filter PerfectSQLiteTests && \
swift test --filter PerfectHTTPTests && \
swift test --skip PerfectSMTPTests --skip PerfectSQLiteTests --skip PerfectHTTPTests