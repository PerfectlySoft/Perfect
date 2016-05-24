import XCTest

import PerfectLibTestSuite

var tests = [XCTestCaseEntry]()
tests += PerfectLibTestSuite.allTests()
XCTMain(tests)
