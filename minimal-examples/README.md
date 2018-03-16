|name|demonstrates|
---|---
http-server|Minimal examples providing an http server
ws-server|Minimal examples providing a ws server (and an http server)
http-client|Minimal examples providing an http client
ws-client|Minimal examples providing a ws client
client-server|Minimal examples providing client and server connections simultaneously

## FAQ

### What should I look at first

Build and install lws itself first, these examples all want to link to it.  Then

`http-server/minimal-http-server`

### Why are most of the sources split into a main C file file and a protocol file?

Lws supports three ways to implement the protocol callback code:

 - you can just add it all in the same source file

 - you can separate it as these examples do, and #include it
   into the main sources

 - you can build it as a standalone plugin that is discovered
   and loaded at runtime.

The way these examples are structured, you can easily also build
the protocol callback as a plugin just with a different
CMakeLists.txt... see https://github.com/warmcat/libwebsockets/tree/master/plugin-standalone
for an example.

### Why would we want the protocol as a plugin?

You will notice a lot of the main C code is the same boilerplate
repeated for each example.  The actual interesting part is in
the protocol callback only.

Lws provides a generic lightweight server app called 'lwsws' that
can be configured by JSON.  Combined with your protocol as a plugin,
it means you don't actually have to make a special server "app"
part, you can just use lwsws and pass per-vhost configuration
from JSON into your protocol.  (Of course in some cases you have
an existing app you are bolting lws on to, then you don't care
about this for that particular case).

Because lwsws has no dependency on whatever your plugin does, it
can mix and match different protocols without needing any code
changes.  It reduces the size of the task to just writing the
code you care about in your protocol handler.

### I get why there is a pss, but why is there a vhd?

The pss is instantiated per-connection.  But there are almost always
other variables that have a lifetime longer than a single connection.

You could make these variables "filescope" one-time globals, but that
means your protocol cannot instantiate multiple times.

Lws supports vhosts (virtual hosts), for example both https://warmcat.com
and https://libwebsockets are running on the same lwsws instance on the
same server and same IP... each of these is a separate vhost.

Your protocol may be enabled on multiple vhosts, each of these vhosts
provides a different vhd specific to the protocol instance on that
vhost.  For example many of the samples keep a linked-list head to
a list of live pss in the vhd... that means it's cleanly a list of
pss opened **on that vhost**.  If another vhost has the protocol
enabled, connections to that will point to a different vhd.

The example "ws-server/minimal-ws-server-threads" demonstrates how to deliver
external configuration data to a specific vhost + protocol
combination using code.  In lwsws, this is simply a matter of setting
the desired JSON config.


