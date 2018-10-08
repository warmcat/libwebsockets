[![Travis Build Status](https://travis-ci.org/warmcat/libwebsockets.svg)](https://travis-ci.org/warmcat/libwebsockets)
[![Appveyor Build status](https://ci.appveyor.com/api/projects/status/qfasji8mnfnd2r8t?svg=true)](https://ci.appveyor.com/project/lws-team/libwebsockets)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/3576/badge.svg)](https://scan.coverity.com/projects/3576)

![lws-overview](./doc-assets/lws-overview.png)

News
----

## v3.0.0 released

See the changelog for info https://github.com/warmcat/libwebsockets/blob/v3.0-stable/changelog

## Major CI improvements for QA

The Travis build of lws done on every commit now runs 

Tests|Count|Explanation
---|---|---
Build / Linux / gcc|14|-Wall -Werror cmake config variants
Build / Mac / Clang|14|-Wall -Werror cmake config variants
Build / Windows / MSVC|7|default
Selftests|openssl:33, mbedtls:33|minimal examples built and run against each other and remote server
attack.sh|225|Correctness, robustness and security tests for http parser
Autobahn Server|480|Testing lws ws client, including permessage-deflate
Autobahn Client|480|Testing lws ws server, including permaessage-deflate
h2spec|openssl:146, mbedtls:146|Http/2 server compliance suite (in strict mode)
h2load|openssl:6, mbedtls:6|Http/2 server load tool (checks 10K / 100K in h1 and h2, at 1, 10, 100 concurrency)
h2load SMP|6|Http/2 and http/1.1 server load checks on SMP server build

The over 1,500 tests run on every commit take most of an hour to complete.
If any problems are found, it breaks the travis build, generating an email.

Current master passes all the tests and these new CI arrangements will help
keep it that way.

## Lws has the first official ws-over-h2 server support

![wss-over-h2](https://libwebsockets.org/sc-wss-over-h2.png)

There's a new standard on the RFC track that enables multiplexing ws connections
over an http/2 link.  Compared to making individual tcp and tls connections for
each ws link back to the same server, this makes your site start up radically
faster, and since all the connections are in one tls tunnel, with considerable memory
reduction serverside.

To enable it on master you just need -DLWS_WITH_HTTP2=1 at cmake.  No changes to
existing code are necessary for either http/2 (if you use the official header creation
apis if you return your own headers, as shown in the test apps for several versions)
or to take advantage of ws-over-h2.  When built with http/2 support, it automatically
falls back to http/1 and traditional ws upgrade if that's all the client can handle.

Currently only Chrome Canary v67 supports this ws-over-h2 encapsulation (chrome
must be started with `--enable-websocket-over-http2` switch to enable it currently)
but the other browsers will catch up soon.

## New "minimal examples"

https://github.com/warmcat/libwebsockets/tree/master/minimal-examples

These are like the test apps, but focus on doing one thing, the best way, with the minimum amount of code.  For example the minimal-http-server serves the cwd on http/1 or http/2 in 50 LOC.  Same thing with tls is just three more lines.

They build standalone, so it's easier to copy them directly to start your own project; they
are CC0 licensed (public domain) to facilitate that.

## Windows binary builds

32- and 64-bit Windows binary builds are available via Appveyor.  Visit [lws on Appveyor](https://ci.appveyor.com/project/lws-team/libwebsockets),
click on a build, the ARTIFACTS, and unzip the zip file at `C:\Program Files (x86)/libwebsockets`.

## Latest Stable

 - v2.4.2 is out... HTTP/2 server support and mbedTLS as a TLS backend.

see the changelog https://github.com/warmcat/libwebsockets/blob/v2.4-stable/changelog

Please note the additional READMEs have moved to ./READMEs/

## ESP32 is supported

ESP32 is now supported in lws!  Download the

 - factory https://github.com/warmcat/lws-esp32-factory and
 - test server app https://github.com/warmcat/lws-esp32-test-server-demos

The ESP32 stuff has my dynamic mbedtls buffer allocation patches applied,
which reduce allocation for small payload TLS links by around 26KiB per connection.

## Support

This is the libwebsockets C library for lightweight websocket clients and
servers.  For support, visit

 https://libwebsockets.org
 https://github.com/warmcat/libwebsockets

and consider joining the project mailing list at

 https://libwebsockets.org/mailman/listinfo/libwebsockets

You can get the latest version of the library from git:

- https://github.com/warmcat/libwebsockets
- https://libwebsockets.org/git

Doxygen API docs for master: https://libwebsockets.org/lws-api-doc-master/html/index.html

