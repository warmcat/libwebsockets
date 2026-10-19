# Http fallback and raw proxying

Lws has several interesting options and features that can be applied to get
some special behaviours... this article discusses them and how they work.

## Overview of normal vhost selection

Lws supports multiple http or https vhosts sharing a listening socket on the
same port.

For unencrypted http, the Host: header is used to select which vhost the
connection should bind to, by comparing what is given there against the
names the server was configured with for the various vhosts.  If no match, it
selects the first configured vhost.

For TLS, it has an extension called SNI (Server Name Indication) which tells
the server early in the TLS handshake the host name the connection is aimed at.
That allows lws to select the vhost early, and use vhost-specific TLS certs
so everything is happy.  Again, if there is no match the connection proceeds
using the first configured vhost and its certs.

## Http(s) fallback options

What happens if you try to connect, eg, an ssh client to the http server port
(this is not an idle question...)?  Obviously the http server part or the tls
part of lws will fail the connection and close it.  (We will look at that flow
in a moment in detail for both unencrypted and tls listeners.)

However if the first configured vhost for the port was created with the
vhost creation info struct `.options` flag `LWS_SERVER_OPTION_FALLBACK_TO_APPLY_LISTEN_ACCEPT_CONFIG`,
then instead of the error, the connection transitions to whatever role was
given in the vhost creation info struct `.listen_accept_role` and `.listen_accept_protocol`.

With lejp-conf / lwsws, the options can be applied to the first vhost using:

```
   "listen-accept-role": "the-role-name",
   "listen-accept-protocol": "the-protocol-name",
   "fallback-listen-accept": "1"
```

See `./minimal-examples/raw/minimal-raw-fallback-http-server` for examples of
all the options in use via commandline flags.

So long as the first packet for the protocol doesn't look like GET, POST, or
a valid tls packet if connection to an https vhost, this allows the one listen
socket to handle both http(s) and a second protocol, as we will see, like ssh.

Notice there is a restriction that no vhost selection processing is possible,
neither for tls listeners nor plain http ones... the packet belonging to a
different protocol will not send any Host: header nor tls SNI.

Therefore although the flags and settings are applied to the first configured
vhost, actually their effect is global for a given listen port.  If enabled,
all vhosts on the same listen port will do the fallback action.

### Plain http flow

![plain http flow](/doc-assets/accept-flow-1.svg)

Normally, if the first received packet does not contain a valid HTTP method,
then the connection is dropped.  Which is what you want from an http server.

However if enabled, the connection can transition to the defined secondary
role / protocol.

|Flag|lejp-conf / lwsws|Function|
|---|---|---|
|`LWS_SERVER_OPTION_FALLBACK_TO_APPLY_LISTEN_ACCEPT_CONFIG`|`"fallback-listen-accept": "1"`|Enable fallback processing|

### TLS https flow

![tls https flow](/doc-assets/accept-flow-2.svg)

If the port is listening with tls, the point that a packet from a different
protocol will fail is earlier, when the tls tunnel is being set up.

|Flag|lejp-conf / lwsws|Function|
|---|---|---|
|`LWS_SERVER_OPTION_FALLBACK_TO_APPLY_LISTEN_ACCEPT_CONFIG`|`"fallback-listen-accept": "1"`|Enable fallback processing|
|`LWS_SERVER_OPTION_REDIRECT_HTTP_TO_HTTPS`|`"redirect-http": "1"`|Treat invalid tls packet as http, issue http redirect to https://|
|`LWS_SERVER_OPTION_ALLOW_HTTP_ON_HTTPS_LISTENER`|`"allow-http-on-https": "1"`|Accept unencrypted http connections on this tls port (dangerous)|

The latter two options are higher priority than, and defeat, the first one.

### Non-http listener

![non-http flow](/doc-assets/accept-flow-3.svg)

It's also possible to skip the fallback processing and just force the first
vhost on the port to use the specified role and protocol in the first place.

|Flag|lejp-conf / lwsws|Function|
|---|---|---|
|LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG|`"apply-listen-accept": "1"`|Force vhost to use listen-accept-role / listen-accept-protocol|

## http CONNECT to a raw protocol

An h1 `CONNECT host:port HTTP/1.1` request can also take its connection out
of http, to a raw protocol, but only where the vhost the request selected
(by its `Host:` header) has a CONNECT mount for exactly that authority.  The
mount's origin type is `LWSMPRO_CONNECT`, its mountpoint is the authority, as
`host:port`, compared in full (the host part without regard to case), and its
origin, or `.protocol`, names the protocol on the vhost that takes the
connection.

```
	static const struct lws_http_mount mount_connect = {
		.mountpoint		= "tunnel.example.com:443",
		.mountpoint_len		= 22,
		.origin			= "my-raw-protocol",
		.origin_protocol	= LWSMPRO_CONNECT,
	};
```

In lwsws / lejp-conf, that is a mount with a `connect://` origin

```
	       {
	        "mountpoint": "tunnel.example.com:443",
	        "origin": "connect://my-raw-protocol"
	       }
```

A CONNECT anywhere else, on a vhost with no CONNECT mount or to an authority
it has none for, is answered `405 Method Not Allowed` with an empty `Allow:`,
and the connection is closed.  CONNECT mounts are never matched by other
requests, and no other mount takes a CONNECT.

The connection goes to the raw-skt role (or the vhost's `listen_accept_role`
if it gives one), bound to the mount's protocol, which gets
`LWS_CALLBACK_RAW_ADOPT`, then the request head itself, and whatever came with
it, as its first `LWS_CALLBACK_RAW_RX`: answering the CONNECT, eg, with
`HTTP/1.1 200 Connection established`, is up to the protocol, as is any
authorization of the request.

Unlike the fallback above, the connection stays subject to the vhost's
validity policy (`.retry_and_idle_policy` in the vhost creation info, or the
context default, 40s / 50s).  Raw has no ping of its own, so lws issues none:
the connection is hung up once `secs_since_valid_hangup` passes without the
protocol calling `lws_validity_confirmed(wsi)`.  A protocol calls it when it
sees the connection is alive in both directions, eg, when the answer to its own
inline PING arrives, and must arrange that to happen more often than the
hangup time.  A policy with `secs_since_valid_hangup` 0 leaves the connection
without a validity timeout.

h2 and h3 have no such transition: a plain CONNECT there is refused, and an
extended CONNECT (RFC 8441 ws, WebTransport) is governed by the vhost's
`SETTINGS_ENABLE_CONNECT_PROTOCOL` and the ws / WebTransport protocol it names.

## Using http(s) fallback with raw-proxy

If enabled for build with `cmake .. -DLWS_ROLE_RAW_PROXY=1 -DLWS_WITH_PLUGINS=1`
then lws includes ready-to-use support for raw tcp proxying.

This can be used standalone on the first vhost on a port, but most intriguingly
it can be specified as the fallback for http(s)...

See `./minimal-examples/raw/minimal-raw-proxy-fallback.c` for a working example.

### fallback with raw-proxy in code

On the first vhost for the port, specify the required "onward" pvo to configure
the raw-proxy protocol...you can adjust the "ipv4:127.0.0.1:22" to whatever you
want...

```
	static struct lws_protocol_vhost_options pvo1 = {
	        NULL,
	        NULL,
	        "onward",		/* pvo name */
	        "ipv4:127.0.0.1:22"	/* pvo value */
	};

	static const struct lws_protocol_vhost_options pvo = {
	        NULL,           	/* "next" pvo linked-list */
	        &pvo1,			/* "child" pvo linked-list */
	        "raw-proxy",		/* protocol name we belong to on this vhost */
	        ""              	/* ignored */
	};
```

... and set up the fallback enable and bindings...

```
	info.options |= LWS_SERVER_OPTION_FALLBACK_TO_APPLY_LISTEN_ACCEPT_CONFIG;
	info.listen_accept_role = "raw_proxy";
	info.listen_accept_proxy = "raw_proxy";
	info.pvo = &pvo;
```

### raw-proxy connection lifetime

When either side of a proxied connection closes, the other side is sent what
the closed side had already sent, and then it is closed too.  It is given 5s
per piece written to take that, so a peer that stops reading cannot hold it
open.

By default an idle proxied connection stays up as long as both sides do, as a
tcp connection would.  The optional pvo "idle-timeout-secs" closes both sides
of a connection once nothing has passed in either direction for that many
seconds, eg, `"idle-timeout-secs": "3600"`.  Only set it for protocols whose
sessions do not legitimately stay quiet for longer (an interactive ssh session
without keepalives may).

### fallback with raw-proxy in JSON conf

On the first vhost for the port, enable the raw-proxy protocol on the vhost and
set the pvo config

```
                "ws-protocols": [{
                        "raw-proxy": {
                         "status": "ok",
                         "onward": "ipv4:127.0.0.1:22"
                        }
                 }],
```

Enable the fallback behaviour on the vhost and the role / protocol binding

```
	"listen-accept-role": "raw-proxy",
	"listen-accept-protocol": "raw-proxy",
	"fallback-listen-accept": "1"
```

### Testing

With this configured, the listen port will function normally for http or https
depending on how it was set up.

But if you try to connect to it with an ssh client, that will also work fine.

The libwebsockets.org server is set up in this way, you can confirm it by
visiting `https://libwebsockets.org` on port 443 as usual, but also trying
`ssh -p 443 invalid@libwebsockets.org`... you will get permission denied from
your ssh client.  With valid credentials in fact that works perfectly for
ssh, scp, git-over-ssh etc all on port 443...

