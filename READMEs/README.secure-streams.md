# Secure Streams

## Default Secure Streams policy

Similar to how low-level lws provides a default protocol
suitable for the common case of http processing that is
available is no explicit user protocol is provided, SS
provides a simple default policy that is suitable for
https connections that are trusted by the system trust
store.

This typically requires:

 1) Openssl, which is wired up to a trust store
 2) Http GET type connections on :443

If you need anything more complicated, you will have to
provide your own policy JSON in place of the default one.

The default policy defines a streamtype "__default" that
allows overriding `${endpoint}` with metadata.  What you
put here may be just the endpoint address like `mysite.com`,
or it can be a url like `https://mysite.com:1234/path`,
the elements given here control the stream address, port and
url path.

## Who can use a Secure Streams proxy

A Secure Streams proxy (`lws_ss_proxy_create()`) makes connections for its
clients using its own policy and whatever credentials it holds: the system
auth token, client certificates, signing keys, cookies.  Anybody who can use
the proxy gets the use of them, so it matters who can reach its listener.

### tcp proxy link

A proxy listening on tcp (`lws_ss_proxy_create()` with a port, eg,
`ssproxy-socket -p <port>`) has **no client authentication**: anybody who can
connect to the port can create any client streamtype in the proxy's policy,
set its metadata, and send payload.  So:

 - With no `.ss_proxy_bind` (or `bind` argument), the listener is bound to
   loopback only: 127.0.0.1, or ::1 in a build without IPv4.

 - A bind that is not a numeric loopback address (127.0.0.0/8, ::1) is
   refused, unless the context creation info sets
   `.ss_proxy_tcp_allow_remote`.  Only set it where the network the port is
   reachable from is itself trusted, eg, firewalled to the containers or VMs
   the clients run in.  lws warns about it when the proxy starts.

The link is not authenticated in the other direction either: a client cannot
tell that what answers on the address is the real proxy.
