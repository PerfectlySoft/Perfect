# Perfect: Server-Side Swift

<p align="center">
    <img src="https://img.shields.io/badge/Swift-6.2%2B-orange.svg?style=flat" alt="Swift 6.2+">
    <img src="https://img.shields.io/badge/Platforms-macOS%2012%2B%20%7C%20Linux-lightgray.svg?style=flat" alt="Platforms macOS 12+ | Linux">
    <a href="LICENSE" target="_blank">
        <img src="https://img.shields.io/badge/License-Apache%202.0-lightgrey.svg?style=flat" alt="License Apache 2.0">
    </a>
</p>

Perfect is a set of focused Swift packages for building servers and talking to the services
behind them: an HTTP(S) server, database drivers, sessions and sign-in, email, push notifications,
FileMaker, payments and everyday utilities. Every package is written for Swift 6 and strict
concurrency, runs on macOS and Linux, keeps its dependencies to a minimum, and is released and
tested on its own.

**This repository used to hold PerfectLib**, the original all-in-one Perfect framework (Swift 3
to 5). PerfectLib is no longer maintained. Its code is preserved on the
[`legacy`](https://github.com/PerfectlySoft/Perfect/tree/legacy) branch, and its tags (the last
is 4.0.1) still resolve. This repository is now the map to the Perfect packages.

## Start here

- **[PerfectTemplate](https://github.com/PerfectlySoft/PerfectTemplate)**: a small web app that
  wires the pieces together (Perfect-NIO, Perfect-CRUD, Perfect-MySQL and Perfect-Logger). Clone
  it to start a project.
- **[Perfect-NIO](https://github.com/PerfectlySoft/Perfect-NIO)**: the HTTP(S) server. Typed,
  composable routes with async handlers, WebSockets, TLS with per-domain certificates, and graceful
  restarts, built on SwiftNIO.

```swift
.package(url: "https://github.com/PerfectlySoft/Perfect-NIO.git", from: "0.2.0"),
```

## Packages

### Server and web

| Package | What it does |
|---|---|
| [Perfect-NIO](https://github.com/PerfectlySoft/Perfect-NIO) | HTTP(S) server on SwiftNIO: typed routes, async handlers, WebSockets, multi-domain TLS, optional admin console |
| [Perfect-Session](https://github.com/PerfectlySoft/Perfect-Session) | Sessions with MySQL, PostgreSQL, SQLite, Redis, MongoDB or in-memory storage, plus CSRF, CORS and cookie helpers |
| [Perfect-Authentication](https://github.com/PerfectlySoft/Perfect-Authentication) | OAuth 2.0 sign-in with PKCE for Google, GitHub, Facebook, Slack, LinkedIn and Salesforce |
| [Perfect-SMTP](https://github.com/PerfectlySoft/Perfect-SMTP) | SMTP client on SwiftNIO: relay or direct-to-MX delivery, DKIM signing, MTA-STS |
| [Perfect-Notifications](https://github.com/PerfectlySoft/Perfect-Notifications) | Apple Push Notification service (APNs) provider client over HTTP/2 |

### Databases

| Package | What it does |
|---|---|
| [Perfect-CRUD](https://github.com/PerfectlySoft/Perfect-CRUD) | `Codable` object-relational mapping: create tables, insert, update, select and join with type-safe queries |
| [Perfect-MySQL](https://github.com/PerfectlySoft/Perfect-MySQL) | MySQL client and Perfect-CRUD driver |
| [Perfect-MariaDB](https://github.com/PerfectlySoft/Perfect-MariaDB) | MariaDB client and Perfect-CRUD driver |
| [Perfect-PostgreSQL](https://github.com/PerfectlySoft/Perfect-PostgreSQL) | PostgreSQL client (libpq) and Perfect-CRUD driver |
| [Perfect-SQLite](https://github.com/PerfectlySoft/Perfect-SQLite) | SQLite client and Perfect-CRUD driver |
| [Perfect-MongoDB](https://github.com/PerfectlySoft/Perfect-MongoDB) | MongoDB client: connection pools, collections, cursors, BSON and GridFS |
| [Perfect-Redis](https://github.com/PerfectlySoft/Perfect-Redis) | Async Redis client |

### FileMaker

| Package | What it does |
|---|---|
| [Perfect-FileMaker](https://github.com/PerfectlySoft/Perfect-FileMaker) | Client for FileMaker Server's XML Custom Web Publishing interface |
| [Perfect-FileMaker-DataAPI](https://github.com/PerfectlySoft/Perfect-FileMaker-DataAPI) | Client for the FileMaker Data API (REST/JSON) |
| [Perfect-FileMaker-AdminAPI](https://github.com/PerfectlySoft/Perfect-FileMaker-AdminAPI) | Client for the FileMaker Server Admin API, with a janitor that clears stale web-publishing sessions |

### Payments

| Package | What it does |
|---|---|
| [Perfect-AuthNet](https://github.com/PerfectlySoft/Perfect-AuthNet) | Authorize.net client: charge, authorize, capture, refund and void, including Accept.js nonces |

### Utilities

| Package | What it does |
|---|---|
| [Perfect-Logger](https://github.com/PerfectlySoft/Perfect-Logger) | File and remote log handlers for [swift-log](https://github.com/apple/swift-log) |
| [Perfect-XML](https://github.com/PerfectlySoft/Perfect-XML) | XML and HTML parsing with XPath, on libxml2 |
| [Perfect-Zip](https://github.com/PerfectlySoft/Perfect-Zip) | Create and safely extract zip archives |
| [Perfect-INIParser](https://github.com/PerfectlySoft/Perfect-INIParser) | INI configuration file parser |

Each package's README lists its requirements, its current release and how to add it to
`Package.swift`. All of them need Swift 6.2 or later and run on macOS 12 or later and Linux.
Perfect-CRUD, Perfect-SQLite, Perfect-Redis, Perfect-FileMaker and Perfect-XML also support iOS.

## Coming from PerfectLib

The packages that PerfectLib and its companions provided have been replaced like this:

| Before | Now |
|---|---|
| Perfect-HTTP, Perfect-HTTPServer, Perfect-Net, Perfect-FastCGI | [Perfect-NIO](https://github.com/PerfectlySoft/Perfect-NIO) |
| Perfect-WebSockets | WebSocket routes in [Perfect-NIO](https://github.com/PerfectlySoft/Perfect-NIO) |
| Perfect-Session-MySQL, -PostgreSQL, -SQLite, -Redis | [Perfect-Session](https://github.com/PerfectlySoft/Perfect-Session) |
| Perfect-OAuth2, Perfect-Turnstile-\*, Perfect-LocalAuthentication-\* | [Perfect-Authentication](https://github.com/PerfectlySoft/Perfect-Authentication) with [Perfect-Session](https://github.com/PerfectlySoft/Perfect-Session) |
| Perfect-CURL | Foundation's `URLSession` |
| Perfect-Crypto | [swift-crypto](https://github.com/apple/swift-crypto) |
| Perfect-Thread | Swift concurrency (`async`/`await`, tasks and actors) |
| PerfectLib's `File` and `Dir` | Foundation's `FileManager` and `FileHandle` |
| PerfectLib's `JSONConvertible` | `Codable` with `JSONEncoder` and `JSONDecoder` |
| PerfectLib's `SysProcess` | Foundation's `Process` |
| PerfectLib's `Log` | [Perfect-Logger](https://github.com/PerfectlySoft/Perfect-Logger) on swift-log |

The old repositories are archived: they stay readable and their tags still resolve, but they don't
get updates. Every package that existed before Swift 6 keeps its old code on a `legacy` branch,
and its README has a migration section.

Some older packages are still being reviewed before they're brought up to date, including
Perfect-Mustache, Perfect-Markdown and Perfect-LDAP. Until then they stay as they are.

## Contributing

Issues and pull requests are welcome on each package's own repository. Please follow the
[Code of Conduct](CODE_OF_CONDUCT.md).

## License

Apache 2.0. See [LICENSE](LICENSE).
