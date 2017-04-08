# Perfect：Swift 语言服务器端软件框架 [English](README.md)
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

## Perfect：Swift 语言服务器端软件框架

Perfect是一组完整、强大的工具箱、软件框架体系和Web应用服务器，可以在Linux、iOS和macOS (OS X)上使用。该软件体系为Swift工程师量身定制了一整套用于开发轻量、易维护、规模可扩展的Web应用及其它REST服务的解决方案，这样Swift工程师就可以实现同时在服务器和客户端上采用同一种语言开发软件项目。

Perfect内建整套工具集，因为无论是客户端还是服务器都能够在此基础之上用同一种计算机语言Swift进行程序开发，因此能够为软件工程师大幅提高工作效率。在全球目前众多的服务器端框架体系和工具箱产品之中，Perfect目前已经成为许多iTunes在线应用程序的可靠后台应用。

无论您是资深程序员还是入门级的软件工程师，本文都能够帮助您快速启动Perfect实现服务器项目开发运行。

## 使用Perfect

### Swift语言兼容性

**目前本项目主干版本基于Xcode 8 GM release发行版本。**

```
Current version: DEVELOPMENT-SNAPSHOT-2016-09-05-a, or Xcode 8 GM release
```


### 快速上手

[在线教程（简体中文）](https://github.com/PerfectlySoft/PerfectDocs/blob/master/guide.zh_CN/gettingStarted.md) 能够帮助您快速开始使用Perfect。该指南包括了如何使用Perfect的几个典型例子。

### 文档
[Perfect帮助文档（简体中文）](https://github.com/PerfectlySoft/PerfectDocs) 如何部署应用程序、如何查找详细文档和帮助。

我们欢迎所有贡献以及对Perfect文档提高的宝贵意见。我们欢迎您为Perfect付出宝贵的支持。如果您发现了任何文字或者内容有错误，或者有任何建议，请[提交一个代码上传请求，或在JIRA上报告问题](http://jira.perfect.org:8080/servicedesk/customer/portal/1/user/login?destination=portal%2F1).

### 社区
我们总会需要您的帮助。如果您真的有想法，不妨加入我们的Perfect支持社区：


[Slack](http://perfect.ly/) | [Twitter](https://twitter.com/perfectlysoft)

### 部署

目前，部署Perfect的方式可以选择[Docker](https://hub.docker.com/r/perfectlysoft/ubuntu/)和[Heroku](https://github.com/PerfectlySoft/Perfect-Heroku-Buildpack)。我们强烈推荐使用这种方式进行部署，因为这些部署方式是通过最新Swift 3.0 和 Perfect 2.0编译完成的。

### 教程和案例

我们的资源库一直在随着社区成员的加入而不断增长，[Swift-Perfect开发社区有许多源程序共分享](https://github.com/PerfectlySoft/PerfectExamples)，都是建立在Perfect程序框架之上。典型例子包括：

- [WebSockets 服务器](https://github.com/PerfectlySoft/PerfectExample-WebSocketsServer)
- [URL 路由](https://github.com/PerfectlySoft/PerfectExample-URLRouting)
- [文件上传](https://github.com/PerfectlySoft/PerfectExample-UploadEnumerator)

[更多例子敬请关注！](https://github.com/PerfectlySoft/PerfectExamples)

[Perfect 1.0教程](http://perfect.org/tutorials.html) (支持 Swift 2.2) 由Swift-Perfect社区成员贡献。或者[从Perfect 2.0开始](http://perfect.org/downloads.html#download-perfect) (支持 Swift 3.0).

## 核心 Perfect 模块

Perfect 项目由若干代码资源库构成，便于您按需查找、下载和安装必要的组件：

- [Perfect](https://github.com/PerfectlySoft/Perfect)：核心的程序库和基础软件框架
- [Perfect Docs](https://github.com/PerfectlySoft/PerfectDocs)：所有必要的程序文档和帮助内容


### 参考和样例

- [Perfect 模板](https://github.com/PerfectlySoft/PerfectTemplate)：一个使用SPM软件包管理器快速上手的入门项目，能够编译为一个独立运行的HTTP服务器。该代码资源非常适合基于Perfect的项目就此开始开发过程。
- [Perfect 样例](https://github.com/PerfectlySoft/PerfectExamples)：所有Perfect 项目的典型样例


### 数据源


- [Perfect Redis](https://github.com/PerfectlySoft/Perfect-Redis)：Redis 数据库连接工具
- [Perfect SQLite](https://github.com/PerfectlySoft/Perfect-SQLite)：SQLite3 数据库连接工具
- [Perfect PostgreSQL](https://github.com/PerfectlySoft/Perfect-PostgreSQL)：PostgreSQL 数据库连接工具
- [Perfect MySQL](https://github.com/PerfectlySoft/Perfect-MySQL)：MySQL 数据库连接工具
- [Perfect MongoDB](https://github.com/PerfectlySoft/Perfect-MongoDB)：MongoDB 数据库连接工具
- [Perfect FileMaker](https://github.com/PerfectlySoft/Perfect-FileMaker)：FileMaker 数据库连接工具

### 工具集

- [Perfect FastCGI Apache 2.4](https://github.com/PerfectlySoft/Perfect-FastCGI-Apache2.4) - Apache 2.4 FastCGI 模块。如果您使用FastCGI用于基础Web服务，请使用该模块
- [Perfect XML](https://github.com/PerfectlySoft/Perfect-XML) - DOM文档对象二级核心只读函数库和XPath路径支持
- [Perfect HTTP Server](https://github.com/PerfectlySoft/Perfect-HTTPServer) - HTTP 1.1标准的 Perfect服务器
- [Perfect Mustache](https://github.com/PerfectlySoft/Perfect-Mustache) - Mustache静态模板支持
- [Perfect CURL](https://github.com/PerfectlySoft/Perfect-CURL) - cURL网页传输支持
- [Perfect WebSockets](https://github.com/PerfectlySoft/Perfect-WebSockets) - 网络套接字WebSockets支持
- [Perfect Zip](https://github.com/PerfectlySoft/Perfect-Zip) - 提供简单的zip压缩和解压缩功能
- [Perfect Notifications](https://github.com/PerfectlySoft/Perfect-Notifications) - 提供苹果消息推送服务支持（APNS）

## 更多内容

Perfect 可以作为一个独立的[HTTP服务器](https://github.com/PerfectlySoft/Perfect-HTTP)或[HTTPS加密服务器](https://github.com/PerfectlySoft/Perfect-HTTPServer)进行运行，或者通过[FastCGI快速网关服务器](https://github.com/PerfectlySoft/Perfect-FastCGI)进行运行。简单来说就是提供一个能够在系统启动是加载的Web服务，从而能够将您自行开发的Swift源码模块根据URL路由要求实现请求/响应，或者根据内建的[Mustache模板](https://github.com/PerfectlySoft/Perfect-Mustache)处理页面。

Perfect是一个完全异步、高性能的网络引擎，并且能够为互联网服务提供大吞吐量控制。该软件体系支持安全套接字（SSL）加密，并且封装了一系列互联网服务器通用的特性，比如[WebSockets](https://github.com/PerfectlySoft/Perfect-WebSockets) 和 [iOS消息推送](https://github.com/PerfectlySoft/Perfect-Notifications)。然而，您的开发可以不必受限于这些选项。

请根据您自己的喜好使用JSON或者其他的模板系统，等等。

### 加入我们的开发社区并贡献自己的力量

Swift-Perfect开发者社区是改进Perfect产品并实现客户支持的关键。

在社区里，您可以通过加入[Perfect Slack 频道](http://perfect.ly)和[Perfect Gitter 频道](https://gitter.im/PerfectlySoft/Perfect)互相帮助、分享技术、互相学习和研究诀窍。任何一种贡献方式我们都非常欢迎：问题汇报、文档更新、补丁修复、编写案例、分享项目或者任何编程窍门，我们相信这些都能够极大地帮助我们的Swift-Perfect社区。

如果您发现了任何文字或者内容有错误，或者有任何建议，请[查看我们的Perfect JIRA资源库](http://jira.perfect.org:8080/secure/Dashboard.jspa).

如果您希望分享一下您的项目、教程或者视频，请将URL共享到我们的推特或者GitHub账号：[Perfect 推特](https://twitter.com/perfectlysoft)。之后我们的Perfect团队会继续推广。

### 行为规范
Perfect团队欢迎所有不同种族、国际、不同年龄、性别、身残志坚、不同学历出身、不同宗教信仰的人为我们的Perfect项目作出贡献。我们承诺为所有项目和公众在线/离线空间提供一个开放、祥和、互相尊重、共同工作的环境。

如果您发现有任何违反上述[行为规范](https://github.com/PerfectlySoft/Perfect/blob/master/CODE_OF_CONDUCT.zh_CN.md)的行为，请[给我们写邮件](mailto:info@perfect.org)。Perfect团队承诺致力于维护上述价值观念以确保所有参与者和用户都能实现对Perfect项目的充分开放的自由使用、自由评论和自由贡献，不需要对任何恐吓而害怕和妥协。

我们会调查任何不当行为与不当言论的投诉，同时我们会对检举人身份保密，便于对各种违法行为进行举报。我们不会容忍在Swift-Perfect社区内的任何直接或间接的骚扰或歧视，并会针对各类不当行为采取适度、公平的纠正措施。

Perfect团队有权删除、修改或拒绝任何不符合我们行为规范的各种言论、代码、版本或问题报告。
