# SS Example "hello_world"

This is the simplest example, showing how to do an https
transaction using Secure Streams (SS).

SS' approach is to segregate "policy" (where and how to connect and authenticate
for particular kinds of connection) from payloads that are transferred on the
connection.  In this case, all the information about the example's policy is in
`example-policy.json`.

|Source|Purpose|
|---|---|
|main.c|boilerplate to create the lws_context and event loop|
|hello_world-ss.c|the secure stream user code|
|example-policy.json|the example policy|

## Build

You should build and install lws itself first.  Then with this directory as the
cwd, you can use `cmake . && make` to build the example.  This produces
`./lws-minimal-ss-hello_world`.

If lws was configured to support SS Proxying with
`-DLWS_WITH_SECURE_STREAMS_PROXY_API=1`, then a second executable is also
produced `./lws-minimal-ss-hello_world-client`.  This does not try to do its own
networking, but instead wants to connect to an SS Proxy process that will fulfil
connections itself using its own policy.

## Running

You should be able to run `./lws-minimal-ss-hello_world` directly and see it
fetch a webpage (just the start and end of each chunk are logged).

To go via the SS Proxy, run `./lws-minimal-ss-hello_world-client` and an SS
Proxy, eg, the example one found in `./minimal-examples/ssproxy/ssproxy-socket`.

## Options

|Commandline option|Meaning|
|---|---|
|-d \<bitmap\>|Enable logging levels (default 1031 (USER, ERR, WARN, NOTICE), 1039 = +INFO, 1151 = +INFO, DEBUG), `-DCMAKE_BUILD_TYPE=DEBUG` needed for logs more verbose that NOTICE
|--ssproxy-port \<port\>|If going via an SS Proxy, default is Unix Domain Socket @proxy.ss.lws, you can force a different proxy's TCP port with this|
|--ssproxy-ads \<ads\>|Set non-default hostname or IP address proxy is on|
|--ssproxy-iface \<iface\>|Set non-default UDS path if starts with +, else interface to bind TCP connection to for proxy|

