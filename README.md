[![Travis Build Status](https://travis-ci.org/warmcat/libwebsockets.svg)](https://travis-ci.org/warmcat/libwebsockets) [![Appveyor Build status](https://ci.appveyor.com/api/projects/status/qfasji8mnfnd2r8t?svg=true)](https://ci.appveyor.com/project/lws-team/libwebsockets) [![Coverity Scan Build Status](https://scan.coverity.com/projects/3576/badge.svg)](https://scan.coverity.com/projects/3576) [![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/2266/badge)](https://bestpractices.coreinfrastructure.org/projects/2266) [![Codacy Badge](https://api.codacy.com/project/badge/Grade/144fb195a83046e484a75c8b4c6cfc99)](https://www.codacy.com/app/lws-team/libwebsockets?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=warmcat/libwebsockets&amp;utm_campaign=Badge_Grade)

# Libwebsockets

Libwebsockets is a simple-to-use, pure C library providing client and server
for **http/1**, **http/2**, **websockets** and other protocols in a security-minded,
lightweight, configurable, scalable and flexible way.  It's easy to build and
cross-build via cmake and is suitable for tasks from embedded RTOS through mass
cloud serving.

[50 minimal examples](https://libwebsockets.org/git/libwebsockets/tree/minimal-examples) for
various scenarios, CC0-licensed (public domain) for cut-and-paste, allow you to get started quickly.

![overview](./doc-assets/lws-overview.svg)

News
----

## v3.1 released: new features in v3.1

 - **lws threadpool** - lightweight pool of pthreads integrated to lws wsi, with all
   synchronization to event loop handled internally, queue for excess tasks
   [threadpool docs](https://libwebsockets.org/git/libwebsockets/tree/lib/misc/threadpool), 
   [threadpool minimal example](https://libwebsockets.org/git/libwebsockets/tree/minimal-examples/ws-server/minimal-ws-server-threadpool), 
   Cmake config: `-DLWS_WITH_THREADPOOL=1`

 - **libdbus support** integrated on lws event loop
   [lws dbus docs](https://libwebsockets.org/git/libwebsockets/tree/lib/roles/dbus), 
   [lws dbus client minimal examples](https://libwebsockets.org/git/libwebsockets/tree/minimal-examples/dbus-client), 
   [lws dbus server minimal examples](https://libwebsockets.org/git/libwebsockets/tree/minimal-examples/dbus-server), 
   Cmake config: `-DLWS_ROLE_DBUS=1`

 - **lws allocated chunks (lwsac)** - helpers for optimized mass allocation of small
   objects inside a few larger malloc chunks... if you need to allocate a lot of
   inter-related structs for a limited time, this removes per-struct allocation
   library overhead completely and removes the need for any destruction handling
   [lwsac docs](https://libwebsockets.org/git/libwebsockets/tree/lib/misc/lwsac), 
   [lwsac minimal example](https://libwebsockets.org/git/libwebsockets/tree/minimal-examples/api-tests/api-test-lwsac), 
   Cmake Config: `-DLWS_WITH_LWSAC=1`

 - **lws tokenizer** - helper api for robustly tokenizing your own strings without
   allocating or adding complexity.  Configurable by flags for common delimiter
   sets and comma-separated-lists in the tokenizer.  Detects and reports syntax
   errors.
   [lws_tokenize docs](https://libwebsockets.org/git/libwebsockets/tree/include/libwebsockets/lws-tokenize.h), 
   [lws_tokenize minimal example / api test](https://libwebsockets.org/git/libwebsockets/tree/minimal-examples/api-tests/api-test-lws_tokenize)

 - **lws full-text search** - optimized trie generation, serialization,
   autocomplete suggestion generation and instant global search support extensible
   to huge corpuses of UTF-8 text while remaining super lightweight on resources.
   [full-text search docs](https://libwebsockets.org/git/libwebsockets/tree/lib/misc/fts), 
   [full-text search minimal example / api test](https://libwebsockets.org/git/libwebsockets/tree/minimal-examples/api-tests/api-test-fts), 
   [demo](https://libwebsockets.org/ftsdemo/), 
   [demo sources](https://libwebsockets.org/git/libwebsockets/tree/plugins/protocol_fulltext_demo.c), 
   Cmake config: `-DLWS_WITH_FTS=1 -DLWS_WITH_LWSAC=1`

 - **gzip + brotli http server-side compression** - h1 and h2 detection of client support
   for server compression, and auto-application to files with mimetypes "text/*",
   "application/javascript" and "image/svg.xml".
   Cmake config: `-DLWS_WITH_HTTP_STREAM_COMPRESSION=1` for gzip, optionally also give
   `-DLWS_WITH_HTTP_BROTLI=1` for preferred `br` brotli compression

 - **managed disk cache** - API for managing a directory containing cached files
   with hashed names, and automatic deletion of LRU files once the cache is
   above a given limit.
   [lws diskcache docs](https://libwebsockets.org/git/libwebsockets/tree/include/libwebsockets/lws-diskcache.h), 
   Cmake config: `-DLWS_WITH_DISKCACHE=1`

 - **http reverse proxy** - lws mounts support proxying h1 or h2 requests to
   a local or remote IP, or unix domain socket over h1.  This allows microservice
   type architectures where parts of the common URL space are actually handled
   by external processes which may be remote or on the same machine.
   [lws gitohashi serving](https://libwebsockets.org/git/) is handled this way.
   [unix domain sockets reverse proxy docs](https://libwebsockets.org/git/libwebsockets/tree/READMEs/README.unix-domain-reverse-proxy.md), 
   CMake config: `-DLWS_WITH_HTTP_PROXY=1` and `-DLWS_UNIX_SOCK=1` for Unix Domain Sockets

 - **update minimal examples for strict Content Security Policy** the minimal
   examples now show the best practices around Content Security Policy and
   disabling inline Javascript.  Updated examples that are served with the
   recommended security restrictions show a new "Strict Content Security Policy"
   graphic.  [Read how to upgrade your applications to use a strict CSP](https://libwebsockets.org/git/libwebsockets/tree/READMEs/README.content-security-policy.md).

 - **release policy docs** - unsure what branch, version or tag to use, or how
   to follow master cleanly?  [Read the release policy docs](https://libwebsockets.org/git/libwebsockets/tree/READMEs/README.release-policy.md)
   which explain how and why lws is developed, released and maintained.

## v3.0.1 released

See the git log for the list of fixes.

## v3.0.0 released

See the changelog for info https://libwebsockets.org/git/libwebsockets/tree/changelog?h=v3.0-stable

## Major CI improvements for QA

The Travis build of lws done on every commit now runs:

Tests|Count|Explanation
---|---|---
Build / Linux / gcc|16|-Wall -Werror cmake config variants
Build / Mac / Clang|16|-Wall -Werror cmake config variants
Build / Windows / MSVC|7|default
Selftests|openssl:43, mbedtls:43|minimal examples built and run against each other and remote server
attack.sh|225|Correctness, robustness and security tests for http parser
Autobahn Server|480|Testing lws ws client, including permessage-deflate
Autobahn Client|480|Testing lws ws server, including permaessage-deflate
h2spec|openssl:146, mbedtls:146|Http/2 server compliance suite (in strict mode)
h2load|openssl:6, mbedtls:6|Http/2 server load tool (checks 10K / 100K in h1 and h2, at 1, 10, 100 concurrency)
h2load SMP|6|Http/2 and http/1.1 server load checks on SMP server build

The over 1,500 tests run on every commit take 1hr 15 of compute time to complete.
If any problems are found, it breaks the travis build, generating an email.

Codacy also checks every patch and the information used to keep lws at zero issues.

Current master is checked by Coverity at least daily and kept at zero issues.

Current master passes all the tests and these new CI arrangements will help
keep it that way.

## Lws has the first official ws-over-h2 server support

![wss-over-h2](./doc-assets/wss2.png)

There's a new [RFC](https://tools.ietf.org/html/rfc8441) that enables multiplexing ws connections
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
must be started with `--enable-websocket-over-http2` switch to enable it currently),
and patches exist for Firefox.  Authors of both browser implementations tested
against the lws server implementation.

## New "minimal examples"

https://libwebsockets.org/git/libwebsockets/tree/minimal-examples

These are like the test apps, but focus on doing one thing, the best way, with the
minimum amount of code.  For example the minimal-http-server serves the cwd on
http/1 or http/2 in 50 LOC.  Same thing with tls is just three more lines.

They build standalone, so it's easier to copy them directly to start your own project; they
are CC0 licensed (public domain) to facilitate that.

## Windows binary builds

32- and 64-bit Windows binary builds are available via Appveyor.  Visit
[lws on Appveyor](https://ci.appveyor.com/project/lws-team/libwebsockets),
click on a build, the ARTIFACTS, and unzip the zip file at `C:\Program Files (x86)/libwebsockets`.

## Support

This is the libwebsockets C library for lightweight websocket clients and
servers.  For support, visit

 https://libwebsockets.org

and consider joining the project mailing list at

 https://libwebsockets.org/mailman/listinfo/libwebsockets

You can get the latest version of the library from git:

- https://libwebsockets.org/git

Doxygen API docs for master: https://libwebsockets.org/lws-api-doc-master/html/index.html

