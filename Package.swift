// swift-tools-version: 5.6
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

#if os(Linux)
let osdep: [Target.Dependency] = ["LinuxBridge"]
let ostag: [Target] = [.target(name: "LinuxBridge"), .target(name: "PerfectCSQLite3")]
let sqldep: [Target.Dependency] = ["PerfectCSQLite3", "PerfectCRUD"]
#else
let osdep: [Target.Dependency] = []
let ostag: [Target] = []
let sqldep: [Target.Dependency] = ["PerfectCRUD"]
#endif
let package = Package(
    name: "Perfect",
    products: [
        .library(name: "PerfectCRUD", targets: ["PerfectCRUD"]),
        .library(name: "PerfectCrypto", targets: ["PerfectCrypto"]),
        .library(name: "PerfectCURL", targets: ["PerfectCURL"]),
        .library(name: "PerfectLib", targets: ["PerfectLib"]),
        .library(name: "PerfectHTTP", targets: ["PerfectHTTP"]),
        .library(name: "PerfectHTTPServer", targets: ["PerfectHTTPServer"]),
        .library(name: "PerfectMustache", targets: ["PerfectMustache"]),
        .library(name: "PerfectNet", targets: ["PerfectNet"]),
        .library(name: "PerfectSMTP", targets: ["PerfectSMTP"]),
        .library(name: "PerfectSQLite", targets: ["PerfectSQLite"]),
        .library(name: "PerfectThread", targets: ["PerfectThread"]),
        .executable(name: "template", targets: ["template"]),
    ],
    dependencies: [ ],
    targets: ostag + [
        .target(name: "COpenSSL"),
        .target(name: "cURL"),
        .target(name: "PerfectCZlib"),
        .target(name: "PerfectCHTTPParser"),
        .target(name: "PerfectLib", dependencies: osdep),
        .target(name: "PerfectThread", dependencies: osdep),
        .target(name: "PerfectCRUD"),
        .target(name: "PerfectCrypto", dependencies: ["PerfectLib", "PerfectThread", "COpenSSL"]),
        .target(name: "PerfectCURL", dependencies: ["cURL", "PerfectLib", "PerfectThread"]),
        .target(name: "PerfectHTTP", dependencies: ["PerfectLib", "PerfectNet"]),
        .target(name: "PerfectHTTPServer", dependencies: ["PerfectCHTTPParser", "PerfectNet", "PerfectHTTP", "PerfectCZlib"]),
        .target(name: "PerfectMustache", dependencies: ["PerfectLib"]),
        .target(name: "PerfectNet", dependencies: ["PerfectCrypto", "PerfectThread"]),
        .target(name: "PerfectSMTP", dependencies: ["PerfectCURL", "PerfectCrypto", "PerfectHTTP"]),
        .target(name: "PerfectSQLite", dependencies: sqldep),
        .testTarget(name: "PerfectCryptoTests", dependencies: ["PerfectCrypto"]),
        .testTarget(name: "PerfectCURLTests", dependencies: ["PerfectCURL"]),
        .testTarget(name: "PerfectHTTPTests", dependencies: ["PerfectHTTP"]),
        .testTarget(name: "PerfectHTTPServerTests", dependencies: ["PerfectHTTPServer"]),
        .testTarget(name: "PerfectLibTests", dependencies: ["PerfectLib"]),
        .testTarget(name: "PerfectMustacheTests", dependencies: ["PerfectMustache"]),
        .testTarget(name: "PerfectNetTests", dependencies: ["PerfectNet"]),
        .testTarget(name: "PerfectSMTPTests", dependencies: ["PerfectSMTP"]),
        .testTarget(name: "PerfectSQLiteTests", dependencies: ["PerfectSQLite"]),
        .testTarget(name: "PerfectThreadTests", dependencies: ["PerfectThread"]),
        .executableTarget(name: "template", dependencies: ["PerfectHTTPServer", "PerfectHTTP"])
    ]
)
