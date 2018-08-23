##Libwebsockets API introduction

Libwebsockets covers a lot of interesting features for people making embedded servers or clients

 - HTTP(S) serving and client operation
 - HTTP/2 support for serving and client operation
 - WS(S) serving and client operation
 - HTTP(S) apis for file transfer and upload
 - HTTP 1 + 2 POST form handling (including multipart / file upload)
 - cookie-based sessions
 - account management (including registration, email verification, lost pw etc)
 - strong SSL / TLS  PFS support (A+ on SSLlabs test)
 - ssh server integration
 - serving gzipped files directly from inside zip files, without conversion
 - support for linux, bsd, windows etc... and very small nonlinux targets like ESP32

Please note you just need in include libwebsockets.h.  It includes all the individual
includes in /usr/include/libwebsockets/ itself.

You can browse by api category <a href="modules.html">here</a>

A collection of READMEs for build, coding, lwsws etc are <a href="pages.html">here</a>

