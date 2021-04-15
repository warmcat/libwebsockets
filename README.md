[![CI status](https://libwebsockets.org/sai/status/libwebsockets)](https://libwebsockets.org/git/libwebsockets) [![Coverity Scan Build Status](https://scan.coverity.com/projects/3576/badge.svg)](https://scan.coverity.com/projects/3576) [![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/2266/badge)](https://bestpractices.coreinfrastructure.org/projects/2266) [![Codacy Badge](https://api.codacy.com/project/badge/Grade/144fb195a83046e484a75c8b4c6cfc99)](https://www.codacy.com/app/lws-team/libwebsockets?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=warmcat/libwebsockets&amp;utm_campaign=Badge_Grade) [![Total alerts](https://img.shields.io/lgtm/alerts/g/warmcat/libwebsockets.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/warmcat/libwebsockets/alerts/) [![Language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/warmcat/libwebsockets.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/warmcat/libwebsockets/context:cpp) [![Language grade: JavaScript](https://img.shields.io/lgtm/grade/javascript/g/warmcat/libwebsockets.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/warmcat/libwebsockets/context:javascript)

# Libwebsockets

Libwebsockets is a simple-to-use, MIT-license, pure C library providing client and server
for **http/1**, **http/2**, **websockets**, **MQTT** and other protocols in a security-minded,
lightweight, configurable, scalable and flexible way.  It's easy to build and
cross-build via cmake and is suitable for tasks from embedded RTOS through mass
cloud serving.

[80+ independent minimal examples](https://libwebsockets.org/git/libwebsockets/tree/minimal-examples) for
various scenarios, CC0-licensed (public domain) for cut-and-paste, allow you to get started quickly.

[There are a lot of READMEs](https://libwebsockets.org/git/libwebsockets/tree/READMEs) on a variety of
topics.

[We do a huge amount of CI testing per push](https://libwebsockets.org/sai/), currently 495 builds on
27 platforms.

![overview](./doc-assets/lws-overview.png)

News
----

## Request for help on mp4 / h.264 / libav*

If you're interested in ws + h.264, there's a 80-90% complete minimal example that needs
help with the mp4 container part, the lws v4l2 integration, MPJPG->h.264 transcoding and
ws transport to MediaSource parts already work.

Take a look at the top two patches on `_v4l2` branch and post on the mailing list or
github to discuss if you can help.

## v4.2 is released

See the [changelog](https://libwebsockets.org/git/libwebsockets/tree/changelog)

## Transition from master branch to main branch

The master->main branch transition happened several months ago, currently master is
still around as a mirror of main.  master branch will go away some time before the
next release.

## Support

This is the libwebsockets C library for lightweight websocket clients and
servers.  For support, visit

 https://libwebsockets.org

and consider joining the project mailing list at

 https://libwebsockets.org/mailman/listinfo/libwebsockets

You can get the latest version of the library from git:

- https://libwebsockets.org/git

Doxygen API docs for development: https://libwebsockets.org/lws-api-doc-master/html/index.html

