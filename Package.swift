// swift-tools-version: 5.4
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

#if os(Linux)
let pkdep: [Package.Dependency] = [
    .package(url: "https://github.com/PerfectlySoft/Perfect-LinuxBridge.git", from: "3.1.0"),
    .package(url: "https://github.com/PerfectlySoft/Perfect-sqlite3-support.git", from: "3.1.1")
]

let sqlite3dep: [Target.Dependency] = [
    .product(name: "PerfectCSQLite3", package: "Perfect-sqlite3-support")
]

let osdep: [Target.Dependency] = sqlite3dep + [.product(name: "LinuxBridge", package: "Perfect-LinuxBridge")]
let sqldep: [Target.Dependency] = sqlite3dep + [.init(stringLiteral: "PerfectCRUD")]
#else
let pkdep: [Package.Dependency] = []
let osdep: [Target.Dependency] = []
let sqldep: [Target.Dependency] = ["PerfectCRUD"]
#endif

let package = Package(
    name: "Perfect",
    products: [
        .library(name: "PerfectAuth", targets: ["PerfectAuth"]),
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
        .executable(name: "httpd", targets: ["httpd"])
    ],
    dependencies: pkdep + [
        .package(url: "https://github.com/PerfectlySoft/Perfect-libcurl.git", from: "2.0.0"),
        .package(url: "https://github.com/PerfectlySoft/Perfect-COpenSSL.git", from: "4.0.2"),
        .package(url: "https://github.com/RockfordWei/Perfect-CZlib-src.git", from: "0.0.6")
    ],
    targets: [
        .target(name: "PerfectAuth", dependencies: ["PerfectCrypto", "PerfectCRUD", "PerfectSQLite"]),
        .target(name: "PerfectCHTTPParser"),
        .target(name: "PerfectLib", dependencies: osdep),
        .target(name: "PerfectThread", dependencies: osdep),
        .target(name: "PerfectCRUD"),
        .target(name: "PerfectCrypto", dependencies: [
            .init(stringLiteral: "PerfectLib"),
            .init(stringLiteral: "PerfectThread"),
            .product(name: "COpenSSL", package: "Perfect-COpenSSL")
        ]),
        .target(name: "PerfectCURL", dependencies: [
            .product(name: "cURL", package: "Perfect-libcurl"),
            .init(stringLiteral: "PerfectLib"),
            .init(stringLiteral: "PerfectThread")
        ]),
        .target(name: "PerfectHTTP", dependencies: ["PerfectLib", "PerfectNet"]),
        .target(name: "PerfectHTTPServer", dependencies: [
            .init(stringLiteral: "PerfectCHTTPParser"),
            .init(stringLiteral: "PerfectCrypto"),
            .init(stringLiteral: "PerfectNet"),
            .init(stringLiteral: "PerfectHTTP"),
            .product(name: "PerfectCZlib", package: "Perfect-CZlib-src")
        ]),
        .target(name: "PerfectMustache", dependencies: ["PerfectLib"]),
        .target(name: "PerfectNet", dependencies: ["PerfectCrypto", "PerfectThread"]),
        .target(name: "PerfectSMTP", dependencies: ["PerfectCURL", "PerfectCrypto", "PerfectHTTP"]),
        .target(name: "PerfectSQLite", dependencies: sqldep),
        .testTarget(name: "PerfectAuthTests", dependencies: [
            "PerfectAuth", "PerfectCRUD", "PerfectCrypto", "PerfectLib", "PerfectSQLite"
        ]),
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
        .executableTarget(name: "httpd", dependencies: [
            "PerfectAuth", "PerfectCrypto", "PerfectLib", "PerfectHTTPServer", "PerfectHTTP",
            "PerfectMustache", "PerfectSMTP", "PerfectSQLite"
		])
    ]
)
