# Perfect: Server-Side Swift [简体中文](README.zh_CN.md)
<p align="center">
    <a href="http://perfect.org/get-involved.html" target="_blank">
        <img src="http://perfect.org/assets/github/perfect_github_2_0_0.jpg" alt="Get Involed with Perfect!" width="854" />
    </a>
</p>

<p align="center">
    <a href="https://github.com/PerfectlySoft/Perfect" target="_blank">
        <img src="http://www.perfect.org/github/Perfect_GH_button_1_Star.jpg" alt="Star Perfect On Github" />
    </a>  
    <a href="http://stackoverflow.com/questions/tagged/perfect" target="_blank">
        <img src="http://www.perfect.org/github/perfect_gh_button_2_SO.jpg" alt="Stack Overflow" />
    </a>  
    <a href="https://twitter.com/perfectlysoft" target="_blank">
        <img src="http://www.perfect.org/github/Perfect_GH_button_3_twit.jpg" alt="Follow Perfect on Twitter" />
    </a>  
    <a href="http://perfect.ly" target="_blank">
        <img src="http://www.perfect.org/github/Perfect_GH_button_4_slack.jpg" alt="Join the Perfect Slack" />
    </a>
</p>

<p align="center">
    <a href="https://developer.apple.com/swift/" target="_blank">
        <img src="https://img.shields.io/badge/Swift-3.0-orange.svg?style=flat" alt="Swift 3.0">
    </a>
    <a href="https://developer.apple.com/swift/" target="_blank">
        <img src="https://img.shields.io/badge/Platforms-OS%20X%20%7C%20Linux%20-lightgray.svg?style=flat" alt="Platforms OS X | Linux">
    </a>
    <a href="http://perfect.org/licensing.html" target="_blank">
        <img src="https://img.shields.io/badge/License-Apache-lightgrey.svg?style=flat" alt="License Apache">
    </a>
    <a href="https://codebeat.co/projects/github-com-perfectlysoft-perfect" target="_blank">
        <img src="https://codebeat.co/badges/85f8f628-6ce8-4818-867c-21b523484ee9" alt="codebeat">
    </a>
    <a href="http://twitter.com/PerfectlySoft" target="_blank">
        <img src="https://img.shields.io/badge/Twitter-@PerfectlySoft-blue.svg?style=flat" alt="PerfectlySoft Twitter">
    </a>
    <a href="http://perfect.ly" target="_blank">
        <img src="http://perfect.ly/badge.svg" alt="Slack Status">
    </a>
</p>

## Perfect: Server-Side Swift

Perfect is a complete and powerful toolbox, framework, and application server for Linux, iOS, and macOS (OS X). It provides everything a Swift engineer needs for developing lightweight, maintainable, and scalable apps and other REST services entirely in the Swift programming language for both client-facing and server-side applications.

Perfect includes a suite of tools that will enhance your productivity as you use only one programming language to build your apps: Swift. The global development community’s most dynamic and popular server-side toolbox and framework available today, Perfect is the backbone for many live web applications and apps available on iTunes.

This guide is designed for developers at all levels of experience to get Perfect up and running quickly.

## Working with Perfect

### Compatibility with Swift

The master branch of this project currently compiles with **Xcode 8.1** or the **Swift 3.0.1** toolchain on Ubuntu.

### Getting Started

[Access a tutorial](https://github.com/PerfectlySoft/PerfectDocs/blob/master/guide/gettingStarted.md) to help you get started using Perfect quickly. It includes straightforward examples of how Perfect can be used.

### Documentation
[Get started working with Perfect](https://github.com/PerfectlySoft/PerfectDocs), deploy your apps, and find more detailed help by consulting our reference library.

We welcome contributions to Perfect’s documentation. If you spot a typo, bug, or other errata, or have additions or suggestions to recommend, please [create a pull request or log an issue in JIRA](http://jira.perfect.org:8080/servicedesk/customer/portal/1/user/login?destination=portal%2F1).

### Community
We all need a little help now and then. If you do too, don’t be shy, ask us or the friendly and supportive Perfect community:


[Slack](http://perfect.ly/) | [Twitter](https://twitter.com/perfectlysoft)

### Deployment

Currently, there are options to deploy Perfect to [Docker](https://hub.docker.com/r/perfectlysoft/ubuntu/) and [Heroku](https://github.com/PerfectlySoft/Perfect-Heroku-Buildpack). We recommend you use these until the other deployment options are updated to compile with Swift 3.0 and Perfect 2.0.

### Samples, Examples, and Tutorials

Our library continues to grow as members of [the Swift-Perfect development community have shared many samples and examples](https://github.com/PerfectExamples) of their projects in Perfect. Examples include:

- [WebSockets Server](https://github.com/PerfectExamples/PerfectExample-WebSocketsServer)
- [URL Routing](https://github.com/PerfectExamples/PerfectExample-URLRouting)
- [Upload Enumerator](https://github.com/PerfectExamples/PerfectExample-UploadEnumerator)

There are [many more examples](https://github.com/PerfectExamples) you can explore. Please share yours!

[Access tutorials for working in Perfect 1.0](http://perfect.org/tutorials.html) (which supports Swift 2.2) published by members of the Swift-Perfect community. Or [start working in Perfect 2.0](http://perfect.org/downloads.html#download-perfect) (supports Swift 3.0).

## Core Perfect Modules

Perfect project is divided into several repositories to make it easy for you to find, download, and install the components you need:

- [Perfect](https://github.com/PerfectlySoft/Perfect) – This repository contains the core PerfectLib and will continue to be the main landing point for the project
- [Perfect Docs](https://github.com/PerfectlySoft/PerfectDocs) – Contains all API reference-related material


### Examples

- [Perfect Template](https://github.com/PerfectlySoft/PerfectTemplate) - A simple starter project which compiles with the Swift Package Manager into a standalone executable HTTP server. This repository is ideal for starting a Perfect-based project
- [Perfect Examples](https://github.com/PerfectExamples) - All the Perfect example projects


### DataSources


- [Perfect Redis](https://github.com/PerfectlySoft/Perfect-Redis) - The Redis database connector
- [Perfect SQLite](https://github.com/PerfectlySoft/Perfect-SQLite) - SQLite3 database connector
- [Perfect PostgreSQL](https://github.com/PerfectlySoft/Perfect-PostgreSQL) - PostgreSQL database connector
- [Perfect MySQL](https://github.com/PerfectlySoft/Perfect-MySQL) - MySQL database connector
- [Perfect MongoDB](https://github.com/PerfectlySoft/Perfect-MongoDB) - MongoDB database connector
- [Perfect FileMaker](https://github.com/PerfectlySoft/Perfect-FileMaker) - FileMaker Server database connector

### Utilities

- [Perfect FastCGI Apache 2.4](https://github.com/PerfectlySoft/Perfect-FastCGI-Apache2.4) - Apache 2.4 FastCGI module; required for the Perfect FastCGI server variant
- [Perfect XML](https://github.com/PerfectlySoft/Perfect-XML) - DOM Core level 2 read-only APIs and XPath support
- [Perfect HTTP Server](https://github.com/PerfectlySoft/Perfect-HTTPServer) - HTTP 1.1 server for Perfect
- [Perfect Mustache](https://github.com/PerfectlySoft/Perfect-Mustache) - Mustache template support for Perfect
- [Perfect CURL](https://github.com/PerfectlySoft/Perfect-CURL) - cURL support for Perfect
- [Perfect WebSockets](https://github.com/PerfectlySoft/Perfect-WebSockets) - WebSockets support for Perfect
- [Perfect Zip](https://github.com/PerfectlySoft/Perfect-Zip) - provides simple zip and unzip functionality
- [Perfect Notifications](https://github.com/PerfectlySoft/Perfect-Notifications) - provides support for Apple Push Notification Service (APNS).

## More about Perfect

Perfect operates using either a standalone [HTTP server](https://github.com/PerfectlySoft/Perfect-HTTP), [HTTPS server](https://github.com/PerfectlySoft/Perfect-HTTPServer), or through [FastCGI server](https://github.com/PerfectlySoft/Perfect-FastCGI). It provides a system for loading your Swift-based modules at startup, for interfacing those modules with its request/response objects, or to the built-in [Mustache template processing system](https://github.com/PerfectlySoft/Perfect-Mustache).

Perfect is built on a completely asynchronous, high-performance networking engine to provide a scalable option for internet services. It supports Secure Sockets Layer (SSL) encryption, and it features a suite of tools commonly required by internet servers such as [WebSockets](https://github.com/PerfectlySoft/Perfect-WebSockets) and [iOS push notifications](https://github.com/PerfectlySoft/Perfect-Notifications), but you are not limited to those options.

Feel free to use your favourite JSON or templating systems, etc.

### Join and Contribute to the Community

The Swift-Perfect developer community is vital to improving Perfect and supporting one another.  

You can help other developers by sharing your expertise and tips, as well as learn from others, by joining the [Perfect Slack channel](http://perfect.ly). Contributions of all kinds are welcome: reporting issues, updating documentation, fixing bugs, building examples, sharing projects, and any other tips that may help the Swift-Perfect community.

If you would like to report an issue, make a new feature request, or help others by working on a known issue, please see the [Perfect JIRA repository](http://jira.perfect.org:8080/secure/Dashboard.jspa).

If you would like to share your example project, tutorial, or video, please share the URL of your work on GitHub and [Twitter](https://twitter.com/perfectlysoft), and the Perfect team will highlight it to the community.

### Code of Conduct
The Perfect team welcomes people of all ethnicities, nationalities, ages, gender, disability, levels of experience, and religious beliefs to use and contribute to the Perfect project. We pledge to foster and enforce a harassment-free environment of openness, respect, and cooperation for everyone in all project and public spaces online or offline.

Please report any behaviour that violates our [Code of Conduct](https://github.com/PerfectlySoft/Perfect/blob/master/CODE_OF_CONDUCT.md) to [info@perfect.org](mailto:info@perfect.org). The Perfect team is committed to enforcing this Code of Conduct to ensure everyone who wishes to use, contribute to, and comment on the Perfect project may do so freely and openly and without fear of reprisal.

We will investigate all complaints of unacceptable or abusive behaviour or comments expediently, and we will maintain the confidentiality of the person who reports any perceived infraction or wrongdoing to us. We will not tolerate any form of direct or indirect harassment or discrimination within the Swift-Perfect community, and will take appropriate, fair, and corrective action to any instance of inappropriate behaviour.

The Perfect team maintains the right to remove, edit, or reject any comments, code, edits, or issues that do not align with our Code of Conduct.
