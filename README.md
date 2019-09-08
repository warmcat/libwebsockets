[![Travis Build Status](https://travis-ci.org/warmcat/libwebsockets.svg)](https://travis-ci.org/warmcat/libwebsockets) [![Appveyor Build status](https://ci.appveyor.com/api/projects/status/qfasji8mnfnd2r8t?svg=true)](https://ci.appveyor.com/project/lws-team/libwebsockets) [![Coverity Scan Build Status](https://scan.coverity.com/projects/3576/badge.svg)](https://scan.coverity.com/projects/3576) [![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/2266/badge)](https://bestpractices.coreinfrastructure.org/projects/2266) [![Codacy Badge](https://api.codacy.com/project/badge/Grade/144fb195a83046e484a75c8b4c6cfc99)](https://www.codacy.com/app/lws-team/libwebsockets?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=warmcat/libwebsockets&amp;utm_campaign=Badge_Grade) [![Total alerts](https://img.shields.io/lgtm/alerts/g/warmcat/libwebsockets.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/warmcat/libwebsockets/alerts/) [![Language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/warmcat/libwebsockets.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/warmcat/libwebsockets/context:cpp) [![Language grade: JavaScript](https://img.shields.io/lgtm/grade/javascript/g/warmcat/libwebsockets.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/warmcat/libwebsockets/context:javascript)

# Libwebsockets

Libwebsockets is a simple-to-use, pure C library providing client and server
for **http/1**, **http/2**, **websockets** and other protocols in a security-minded,
lightweight, configurable, scalable and flexible way.  It's easy to build and
cross-build via cmake and is suitable for tasks from embedded RTOS through mass
cloud serving.

[50 minimal examples](https://libwebsockets.org/git/libwebsockets/tree/minimal-examples) for
various scenarios, CC0-licensed (public domain) for cut-and-paste, allow you to get started quickly.

![overview](./doc-assets/lws-overview.png)

News
----

## UDP integration with `lws_retry`

UDP support in lws has new helper that allow `lws_retry` to be applied for retry,
and the ability to synthesize rx and tx udp packetloss systemwide to confirm
retry strategies.  Since multiple transactions may be in flight on one UDP
socket, the support relies on an `lws_sul` in the transaction object to manage
the transaction retries individually.

See `READMEs/README.udp.md` for details.

## `lws_system`: system state and notification handlers

Lws now has the concept of systemwide state held in the context... this is to
manage that there may be multiple steps that need the network before it's possible
for the user code to operate normally.  The steps defined are

`CONTEXT_CREATED`, `INITIALIZED`, `TIME_VALID`, `POLICY_VALID`, `OPERATIONAL` and
`POLICY_INVALID`.  OPERATIONAL is the state where user code can run normally.

User and other parts of lws can hook notifier callbacks to receive and be able to
veto system state changes, either definitively or because they have been triggered
to perform a step asynchronously and will move the state on themselves when it
completes.

By default just after context creation, lws attempts to move straight to OPERATIONAL.
If no notifier interecepts it, it will succeed to do that and operate in a
backwards-compatible way.

See `READMEs/README.lws_system.md` for details.

## `lws_system`: HAL ops struct

Lws allows you to define a standardized ops struct at context creation time so your
user code can get various information like device serial number without embedding
system-specific code throughout the user code.  It can also perform some generic
functions like requesting a device reboot.

See `READMEs/README.lws_system.md` for details.

## Connection Validity tracking

Lws now allows you to apply a policy for how long a network connection may go
without seeing something on it that confirms it's still valid in the sense of
passing traffic cohernetly both ways.  There's a global policy in the context
which defaults to 5m before it produces a PING if possible, and 5m10 before
the connection will be hung up, user code can override this in the context,
vhost (for server) and client connection info (for client).

An api `lws_validity_confirmed(wsi)` is provided so user code can indicate
that it observed traffic that must mean the connection is passing traffic in
both directions to and from the peer.  In the absence of these confirmations
lws will generate PINGs and take PONGs as the indication of validity.

## `lws_system`: Async DNS support

Master now provides optional Asynchronous (ie, nonblocking) DNS resolving.  Enable
with `-DLWS_WITH_SYS_ASYNC_DNS=1` at cmake.  This provides a quite sophisticated
ipv4 + ipv6 capable resolver that autodetects the dns server on several platforms
and operates a UDP socket to its port 53 to produce and parse DNS packets
from the event loop.  And of course, it's extremely compact.

It broadly follows the getaddrinfo style api, but instead of creating the results
on the heap for each caller, it caches a single result according to the TTL and
then provides refcounted const pointers to the cached result to callers.  While
there are references on the cached result it can't be reaped.

See `READMEs/README.async-dns.md` for detailed information on how it works, along
with `api-tests/api-test-async-dns` minimal example.

## Detailed Latency

You can now opt to measure and store us-resolution statistics on effective
latencies for client operations, and easily spool them to a file in a
format suitable for gnuplot, or handle in your own callback.  Enable
`-DLWS_WITH_DETAILED_LATENCY=1` in cmake to build it into lws.

If you are concerned about operation latency or potential blocking from
user code, or behaviour under load, or latency variability on specific
platforms, you can get real numbers on your platform using this.

Timings for all aspects of events on connections are recorded, including
the time needed for name resolution, setting up the connection, tls
negotiation on both client and server sides, and each read and write.

See `READMEs/README.detailed-latency.md` for how to use it.

## Client connection logic rewrite

Lws master now makes much better use of the DNS results for ipv4 and ipv6... it
will iterate through them automatically making the best use it can of what's
provided and attempting new connections for each potentially usable one in turn
before giving up on the whole client connection attempt.

If ipv6 is disabled at cmake it can only use A / ipv4 records, but if ipv6 is
enabled, it tries both; if only ipv6 is enabled it promotes ipv4 to
::ffff:1.2.3.4 IPv4-in-IPv6 addresses.

## New network helpers for ipv4 and ipv6

An internal union `lws_sockaddr46` that combines `struct sockaddr_in` and
`struct sockaddr_in6` is now public, and there are helpers that can parse (using
`lws_tokenize`) any valid numeric representation for ipv4 and ipv6 either
into byte arrays and lengths, or directly to and from `lws_sockaddr46`.

## h2 long poll support

Lws now supports the convention that half-closing an h2 http stream may make
the stream 'immortal', in terms of not being bound by normal timeouts.  For
the client side, there's an api that can be applied to the client stream to
make it transition to this "read-only" long poll mode.

See `READMEs/README.h2-long-poll.md` for full details, including how to test
it with the minimal examples.

## h1 client parser improvements

H1 is not so simple to parse because the header length is not known until it
has been fully parsed.  The next header, or http body may be directly coalesced
with the header as well.  Lws has supported bulk h1 parsing from a buffer for a
long time, but on clientside due to interactions with http proxying it had
been stuck parsing the header bytewise out of the tls buffer.  In master,
everything now bulk parses from a buffer and uses a buflist to pass leftovers
through the event loop cleanly.

## `lws_sul` time refactor

Just before v3.2 there was a big refactor about how lws handles time.  It now
explicitly schedules anything that may happen in the future on a single, sorted
linked-list, at us resolution.  When entering a poll wait (or returning to an
event lib loop) it checks the interval between now and the earliest event on the
list to figure out how long to wait if there are no network events.  For the
event loop case, it sets a native event lib timer to enforce it.

See `READMEs/README.lws_sul.md` for more details and a handy api where you can
schedule your own arbitrary callbacks using this system.

## Master is now MIT-licensed

Libwebsockets master is now under the MIT license. See ./LICENSE.

## Support

This is the libwebsockets C library for lightweight websocket clients and
servers.  For support, visit

 https://libwebsockets.org

and consider joining the project mailing list at

 https://libwebsockets.org/mailman/listinfo/libwebsockets

You can get the latest version of the library from git:

- https://libwebsockets.org/git

Doxygen API docs for master: https://libwebsockets.org/lws-api-doc-master/html/index.html

