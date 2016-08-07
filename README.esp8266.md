ESP8266 lws port
----------------

lws can now work well on the ESP8266.

You should get the ESP8266 Espressif SDK-based project here

https://github.com/lws-team/esplws

which includes lws as an "app" in the build.  The project provides full AP-based setup over the web, and once the device has been configured to associate to a local AP, a separate station vhost with the lws test protocols.

Instructions for building that are here

https://github.com/lws-team/esplws/blob/master/README.md

There are also instructions there for how to remove the test apps from the build and customize your own station content.


Information about lws integration on ESP8266
--------------------------------------------

The following existing lws features are used to make a nice integration:

 - vhosts: there are separate vhosts for the configuration AP mode and the normal station mode.

 - file_ops: the lws file operations are overridden and handled by a ROMFS parser

 - mounts: mounts are used to serve files automatically from the ROMFS

 - plugins: standalone protocol plugins are included into the build, so there are clean individual implementations for each protocol, while everything is statically linked

 - lws stability and security features like bytewise parsers, sophisticated timeouts, http/1.1 keepalive support


