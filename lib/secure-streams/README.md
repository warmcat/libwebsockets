# Secure Streams

Secure Streams is a networking api that strictly separates payload from any
metadata.  That includes the client endpoint address for the connection, the tls
trust chain and even the protocol used to connect to the endpoint.

The user api just receives and transmits payload, and receives advisory
connection state information.

The details about how the connections for different types of secure stream should
be made are held in JSON "policy database" initially passed in to the context
creation, but able to be updated from a remote copy.

Both client and server networking can be handled using Secure Streams APIS.

![overview](../doc-assets/ss-operation-modes.png)

## Secure Streams CLIENT State lifecycle

![overview](../doc-assets/ss-state-flow.png)

Secure Streams are created using `lws_ss_create()`, after that they may acquire
underlying connections, and lose them, but the lifecycle of the Secure Stream
itself is not directly related to any underlying connection.

Once created, Secure Streams may attempt connections, these may fail and once
the number of failures exceeds the count of attempts to conceal in the retry /
backoff policy, the stream reaches `LWSSSCS_ALL_RETRIES_FAILED`.  The stream becomes
idle again until another explicit connection attempt is given.

Once connected, the user code can use `lws_ss_request_tx()` to ask for a slot
to write to the peer, when this if forthcoming the tx handler can send a message.
If the underlying protocol gives indications of transaction success, such as,
eg, a 200 for http, or an ACK from MQTT, the stream state is called back with
an `LWSSSCS_QOS_ACK_REMOTE` or `LWSSSCS_QOS_NACK_REMOTE`.

## SS Callback return handling

SS state(), rx() and tx() can indicate with their return code some common
situations that should be handled by the caller.

Constant|Scope|Meaning
---|---|---
LWSSSSRET_TX_DONT_SEND|tx|This opportunity to send something was passed on
LWSSSSRET_OK|state, rx, tx|No error, continue doing what we're doing
LWSSSSRET_DISCONNECT_ME|state, rx|assertively disconnect from peer
LWSSSSRET_DESTROY_ME|state, rx|Caller should now destroy the stream itself
LWSSSSRET_SS_HANDLE_DESTROYED|state|Something handled a request to destroy the stream

Destruction of the stream we're calling back on inside the callback is tricky,
it's preferable to return `LWSSSSRET_DESTROY_ME` if it is required, and let the
caller handle it.  But in some cases, helpers called from the callbacks may
destroy the handle themselves, in that case the handler should return
`LWSSSSRET_SS_HANDLE_DESTROYED` indicating that the handle is already destroyed.

## Secure Streams SERVER State lifecycle

![overview](../doc-assets/ss-state-flow-server.png)

You can also run servers defined using Secure Streams, the main difference is
that the user code must assertively create a secure stream of the server type
in order to create the vhost and listening socket.  When this stream is
destroyed, the vhost is destroyed and the listen socket closed, otherwise it
does not perform any rx or tx, it just represents the server lifecycle.

When client connections randomly arrive at the listen socket, new Secure Stream
objects are created along with accept sockets to represent each client
connection.  As they represent the incoming connection, their lifecycle is the
same as that of the underlying connection.  There is no retry concept since as
with eg, http servers, the clients may typically not be routable for new
connections initiated by the server.

Since connections at socket level are already established, new connections are
immediately taken through CREATING, CONNECTING, CONNECTED states for
consistency.

Some underlying protocols like http are "transactional", the server receives
a logical request and must reply with a logical response.  The additional
state `LWSSSCS_SERVER_TXN` provides a point where the user code can set
transaction metadata before or in place of sending any payload.  It's also
possible to defer this until any rx related to the transaction was received,
but commonly with http requests, there is no rx / body.  Configuring the
response there may look like

```
		/*
		 * We do want to ack the transaction...
		 */
		lws_ss_server_ack(m->ss, 0);
		/*
		 * ... it's going to be text/html...
		 */
		lws_ss_set_metadata(m->ss, "mime", "text/html", 9);
		/*
		 * ...it's going to be 128 byte (and request tx)
		 */
		lws_ss_request_tx_len(m->ss, 128);
```

Otherwise the general api usage is very similar to client usage.

## Convention for rx and tx callback return

Function|Return|Meaning
---|---|---
tx|`LWSSSSRET_OK`|Send the amount of `buf` stored in `*len`
tx|`LWSSSSRET_TX_DONT_SEND`|Do not send anything
tx|`LWSSSSRET_DISCONNECT_ME`|Close the current connection
tx|`LWSSSSRET_DESTROY_ME`|Destroy the Secure Stream
rx|>=0|accepted
rx|<0|Close the current connection

# JSON Policy Database

Example JSON policy... formatting is shown for clarity but whitespace can be
omitted in the actual policy.

Ordering is not critical in itself, but forward references are not allowed,
things must be defined before they are allowed to be referenced later in the
JSON.


```
{
	"release": "01234567",
	"product": "myproduct",
	"schema-version": 1,
	"retry": [{
		"default": {
			"backoff": [1000, 2000, 3000, 5000, 10000],
			"conceal": 5,
			"jitterpc": 20
		}
	}],
	"certs": [{
		"isrg_root_x1": "MIIFazCCA1OgAw...AnX5iItreGCc="
	}, {
		"LEX3_isrg_root_x1": "MIIFjTCCA3WgAwIB...WEsikxqEt"
	}],
	"trust_stores": [{
		"le_via_isrg": ["isrg_root_x1", "LEX3_isrg_root_x1"]
	}],
	"s": [{
		"mintest": {
			"endpoint": "warmcat.com",
			"port": 4443,
			"protocol": "h1get",
			"aux": "index.html",
			"plugins": [],
			"tls": true,
			"opportunistic": true,
			"retry": "default",
			"tls_trust_store": "le_via_isrg"
		}
	}]
}
```

### `Release`

Identifies the policy version

### `Product`

Identifies the product the policy should apply to

### `Schema-version`

The minimum version of the policy parser required to parse this policy

### `via-socks5`

Optional redirect for Secure Streams client traffic through a socks5
proxy given in the format `address:port`, eg, `127.0.0.1:12345`.

### `retry`

A list of backoff schemes referred to in the policy

### `backoff`

An array of ms delays for each retry in turn

### `conceal`

The number of retries to conceal from higher layers before giving errors.  If
this is larger than the number of times in the backoff array, then the last time
is used for the extra delays

### `jitterpc`

Percentage of the delay times mentioned in the backoff array that may be
randomly added to the figure from the array.  For example with an array entry of
1000ms, and jitterpc of 20%, actual delays will be chosen randomly from 1000ms
through 1200ms.  This is to stop retry storms triggered by a single event like
an outage becoming synchronized into a DoS.

### `certs`

Certificates needed for validation should be listed here each with a name.  The
format is base64 DER, which is the same as the part of PEM that is inside the
start and end lines.

### `trust_stores`

Chains of certificates given in the `certs` section may be named and described
inside the `trust_stores` section.  Each entry in `trust_stores` is created as
a vhost + tls context with the given name.  Stream types can later be associated
with one of these to enforce validity checking of the remote server.

Entries should be named using "name" and the stack array defined using "stack"

### `s`

These are an array of policies for the supported stream type names.

### `server`

**SERVER ONLY**: if set to `true`, the policy describes a secure streams
server.

### `endpoint`

**CLIENT**: The DNS address the secure stream should connect to.

This may contain string symbols which will be replaced with the
corresponding streamtype metadata value at runtime.  Eg, if the
streamtype lists a metadata name "region", it's then possible to
define the endpoint as, eg, `${region}.mysite.com`, and before
attempting the connection setting the stream's metadata item
"region" to the desired value, eg, "uk".

If the endpoint string begins with `+`, then it's understood to
mean a connection to a Unix Domain Socket, for Linux `+@` means
the following Unix Domain Socket is in the Linux Abstract
Namespace and doesn't have a filesystem footprint.  This is only
supported on unix-type and windows platforms and when lws was
configured with `-DLWS_UNIX_SOCK=1`

**SERVER**: If given, the network interface name or IP address the listen socket
should bind to.

### `port`

**CLIENT**: The port number as an integer on the endpoint to connect to

**SERVER**: The port number the server will listen on

### `protocol`

**CLIENT**: The wire protocol to connect to the endpoint with.  Currently
supported streamtypes are

|Wire protocol|Description|
|---|---|
|h1|http/1|
|h2|http/2|
|ws|http/1 Websockets|
|mqtt|mqtt 3.1.1|
|raw||

Raw protocol is a bit different than the others in that there is no protocol framing,
whatever is received on the connection is passed to the user rx callback and whatever
the tx callback provides is issued on to the connection.  Because tcp can be
arbitrarily fragmented by any intermediary, such streams have to be regarded as an
ordered bytestream that may be fragmented at any byte without any meaning in terms
of message boundaries, for that reason SOM and EOM are ignored with raw.

### `allow_redirects`

By default redirects are not followed, if you wish a streamtype to observe them, eg,
because that's how it responds to a POST, set `"allow_redirects": true`

### `tls`

Set to `true` to enforce the stream travelling in a tls tunnel

### `client cert`

Set if the stream needs to authenticate itself using a tls client certificate.
Set to the certificate index counting from 0+.  The certificates are managed
using lws_sytstem blobs.

### `opportunistic`

Set to `true` if the connection may be left dropped except when in use

### `nailed_up`

Set to `true` to have lws retry if the connection carrying this stream should
ever drop.

### `retry`

The name of the policy described in the `retry` section to apply to this
connection for retry + backoff

### `timeout_ms`

Optional timeout associated with streams of this streamtype.

If user code applies the `lws_ss_start_timeout()` api on a stream with a
timeout of LWSSS_TIMEOUT_FROM_POLICY, the `timeout_ms` entry given in the
policy is applied.

### `tls_trust_store`

The name of the trust store described in the `trust_stores` section to apply
to validate the remote server cert.

### `server_cert`

**SERVER ONLY**: subject to change... the name of the x.509 cert that is the
server's tls certificate

### `server_key`

**SERVER ONLY**: subject to change... the name of the x.509 cert that is the
server's tls key

### `swake_validity`

Set to `true` if this streamtype is important enough for the functioning of the
device that its locally-initiated periodic connection validity checks of the
interval described in the associated retry / backoff selection, are important
enough to wake the whole system from low power suspend so they happen on
schedule.

## http transport

### `http_method`

HTTP method to use with http-related protocols, like GET or POST.
Not required for ws.

### `http_expect`

Optionally indicates that success for HTTP transactions using this
streamtype is different than the default 200 - 299.

Eg, you may choose to set this to 204 for Captive Portal Detect usage
if that's what you expect the server to reply with to indicate
success.  In that case, anything other than 204 will be treated as a
connection failure.

### `http_fail_redirect`

Set to `true` if you want to fail the connection on meeting an
http redirect.  This is needed to, eg, detect Captive Portals
correctly.  Normally, if on https, you would want the default behaviour
of following the redirect.

### `http_url`

Url path to use with http-related protocols

The URL path can include metatadata like this

"/mypath?whatever=${metadataname}"

${metadataname} will be replaced by the current value of the
same metadata name.  The metadata names must be listed in the
"metadata": [ ] section.

### `http_auth_header`

The name of the header that takes the auth token, with a trailing ':', eg

```
  "http_auth_header": "authorization:"
```

### `http_dsn_header`

The name of the header that takes the dsn token, with a trailing ':', eg

```
  "http_dsn_header": "x-dsn:"
```

### `http_fwv_header`

The name of the header that takes the firmware version token, with a trailing ':', eg

```
  "http_fwv_header": "x-fw-version:"
```

### `http_devtype_header`

The name of the header that takes the device type token, with a trailing ':', eg

```
  "http_devtype_header": "x-device-type:"
```

### `http_auth_preamble`

An optional string that precedes the auth token, eg

```
 "http_auth_preamble": "bearer "
```

### `auth_hexify`

Convert the auth token to hex ('A' -> "41") before transporting.  Not necessary if the
auth token is already in printable string format suitable for transport.  Needed if the
auth token is a chunk of 8-bit binary.

### `nghttp2_quirk_end_stream`

Set this to `true` if the peer server has the quirk it won't send a response until we have
sent an `END_STREAM`, even though we have sent headers with `END_HEADERS`.

### `h2q_oflow_txcr`

Set this to `true` if the peer server has the quirk it sends an maximum initial tx credit
of 0x7fffffff and then later increments it illegally.

### `http_multipart_ss_in`

Indicates that SS should parse any incoming multipart mime on this stream

### `http_multipart_name`

Indicates this stream goes out using multipart mime, and provides the name part of the
multipart header

### `http_multipart_filename`

Indicates this stream goes out using multipart mime, and provides the filename part of the
multipart header

### `http_multipart_content_type`

The `content-type` to mark up the multipart mime section with if present

### `http_www_form_urlencoded`

Indicate the data is sent in `x-www-form-urlencoded` form

### `rideshare`

For special cases where one logically separate stream travels with another when using this
protocol.  Eg, a single multipart mime transaction carries content from two or more streams.

## ws transport

### `ws_subprotocol`

** CLIENT **: Name of the ws subprotocol to request from the server

** SERVER **: Name of the subprotocol we will accept

### `ws_binary`

Use if the ws messages are binary

## MQTT transport

### `mqtt_topic`

Set the topic this streamtype uses for writes

### `mqtt_subscribe`

Set the topic this streamtype subscribes to

### `mqtt qos`

Set the QOS level for this streamtype

### `mqtt_keep_alive`

16-bit number representing MQTT keep alive for the stream.

This is applied at connection time... where different streams may bind to the
same underlying MQTT connection, all the streams should have an identical
setting for this.

### `mqtt_clean_start`

Set to true if the connection should use MQTT's "clean start" feature.

This is applied at connection time... where different streams may bind to the
same underlying MQTT connection, all the streams should have an identical
setting for this.

### `mqtt_will_topic`

Set the topic of the connection's will message, if any (there is none by default).

This is applied at connection time... where different streams may bind to the
same underlying MQTT connection, all the streams should have an identical
setting for this.

### `mqtt_will_message`

Set the content of the connect's will message, if any (there is none by default).

This is applied at connection time... where different streams may bind to the
same underlying MQTT connection, all the streams should have an identical
setting for this.

### `mqtt_will_qos`

Set the QoS of the will message, if any (there is none by default).

This is applied at connection time... where different streams may bind to the
same underlying MQTT connection, all the streams should have an identical
setting for this.

### `mqtt_will_retain`

Set to true if the connection should use MQTT's "will retain" feature, if there
is a will message (there is none by default).

This is applied at connection time... where different streams may bind to the
same underlying MQTT connection, all the streams should have an identical
setting for this.

## Loading and using updated remote policy

If the default, hardcoded policy includes a streamtype `fetch_policy`,
during startup when lws_system reaches the POLICY state, lws will use
a Secure Stream of type `fetch_policy` to download, parse and update
the policy to use it.

The secure-streams-proxy minimal example shows how this is done and
fetches its real policy from warmcat.com at startup using the built-in
one.

## Applying streamtype policy overlays

This is intended for modifying policies at runtime for testing, eg, to
force error paths to be taken.  After the main policy is processed, you
may parse additional, usually smaller policy fragments on top of it.

Where streamtype names in the new fragment already exist in the current
parsed policy, the settings in the fragment are applied over the parsed
policy, overriding settings.  There's a simple api to enable this by
giving it the override JSON in one string

```
int
lws_ss_policy_overlay(struct lws_context *context, const char *overlay);
```

but there are also other apis available that can statefully process
larger overlay fragments if needed.

An example overlay fragment looks like this

```
	{ "s": [{ "captive_portal_detect": {
		"endpoint": "google.com",
		"http_url": "/",
		"port": 80
	}}]}
```

ie the overlay fragment completely follows the structure of the main policy,
just misses out anything it doesn't override.

Currently ONLY streamtypes may be overridden.

You can see an example of this in use in `minimal-secure-streams` example
where `--force-portal` and `--force-no-internet` options cause the captive
portal detect streamtype to be overridden to force the requested kind of
outcome.

## Captive Portal Detection

If the policy contains a streamtype `captive_portal_detect` then the
type of transaction described there is automatically performed after
acquiring a DHCP address to try to determine the captive portal
situation.

```
		"captive_portal_detect": {
                        "endpoint": "connectivitycheck.android.com",
                        "port": 80,
                        "protocol": "h1",
                        "http_method": "GET",
                        "http_url": "generate_204",
                        "opportunistic": true,
                        "http_expect": 204,
			"http_fail_redirect": true
                }
```

## Stream serialization and proxying

By default Secure Streams expects to make the outgoing connection described in
the policy in the same process / thread, this suits the case where all the
participating clients are in the same statically-linked image.

In this case the `lws_ss_` apis are fulfilled locally by secure-streams.c and
policy.c for policy lookups.

However it also supports serialization, where the SS api can be streamed over
another transport such as a Unix Domain Socket connection.  This suits the case
where the clients are actually in different processes in, eg, Linux or Android.

In those cases, you run a proxy process (minimal-secure-streams-proxy) that
listens on a Unix Domain Socket and is connected to by one or more other
processes that pass their SS API activity to the proxy for fulfilment (or
onward proxying).

Each Secure Stream that is created then in turn creates a private Unix Domain
Socket connection to the proxy for each stream.

In this case the proxy uses secure-streams.c and policy.c as before to fulfil
the inbound proxy streams, but uses secure-streams-serialize.c to serialize and
deserialize the proxied SS API activity.  The proxy clients define
LWS_SS_USE_SSPC either very early in their sources before the includes, or on
the compiler commandline... this causes the lws_ss_ apis to be replaced at
preprocessor time with lws_sspc_ equivalents.  These serialize the api action
and pass it to the proxy over a Unix Domain Socket for fulfilment, the results
and state changes etc are streamed over the Unix Domain Socket and presented to
the application exactly the same as if it was being fulfilled locally.

To demonstrate this, some minimal examples, eg, minimal-secure-streams and
mimimal-secure-streams-avs build themselves both ways, once with direct SS API
fulfilment and once with Unix Domain Socket proxying and -client appended on the
executable name.  To test the -client variants, run minimal-secure-streams-proxy
on the same machine.

## Complicated scenarios with secure streams proxy

As mentioned above, Secure Streams has two modes, by default the application
directly parses the policy and makes the outgoing connections itself.
However when configured at cmake with

```
-DLWS_WITH_SOCKS5=1 -DLWS_WITH_SECURE_STREAMS=1 -DLWS_WITH_SECURE_STREAMS_PROXY_API=1 -DLWS_WITH_MINIMAL_EXAMPLES=1
```

and define `LWS_SS_USE_SSPC` when building the application, applications forward
their network requests to a local or remote SS proxy for fulfilment... and only
the SS proxy has the system policy.  By default, the SS proxy is on the local
machine and is connected to via a Unix Domain Socket, but tcp links are also
possible.  (Note the proxied traffic is not encrypyed by default.)

Using the configuration above, the example SS applications are built two ways,
once for direct connection fulfilment (eg, `./bin/lws-minimal-secure-streams`),
and once with `LWS_SS_USE_SSPC` also defined so it connects via an SS proxy,
(eg, `./bin/lws-minimal-secure-streams-client`).

## Testing an example scenario with SS Proxy and socks5 proxy

```
 [ SS application ] --- tcp --- [ socks 5 proxy ] --- tcp --- [ SS proxy ] --- internet
```

In this scenario, everything is on localhost, the socks5 proxy listens on :1337 and
the SS proxy listens on :1234.  The SS application connects to the socks5
proxy to get to the SS proxy, which then goes out to the internet

### 1 Start the SS proxy

Tell it to listen on lo interface on port 1234 

```
$ ./bin/lws-minimal-secure-streams-proxy -p 1234 -i lo
```

### 2 Start the SOCKS5 proxy

```
$ ssh -D 1337 -N -v localhost
```

The -v makes connections to the proxy visible in the terminal for testing

### 3 Run the SS application

The application is told to make all connections via the socks5 proxy at
127.0.0.1:1337, and to fulfil its SS connections via an SS proxy, binding
connections to 127.0.0.1 (ipv4 lo interface, -1), to 127.0.0.1:1234 (-a/-p).

```
socks_proxy=127.0.0.1:1337 ./bin/lws-minimal-secure-streams-client -p 1234 -i 127.0.0.1 -a 127.0.0.1
```

You can confirm this goes through the ssh socks5 proxy to get to the SS proxy
and fulfil the connection.

## Using static policies

If one of your targets is too constrained to make use of dynamic JSON policies, but
using SS and the policies is attractive for wider reasons, you can use a static policy
built into the firmware for the constrained target.

The secure-streams example "policy2c" (which runs on the build machine, not the device)

https://libwebsockets.org/git/libwebsockets/tree/minimal-examples/secure-streams/minimal-secure-streams-policy2c

accepts a normal JSON policy on stdin, and emits a C code representation that can be
included directly in the firmware.

https://libwebsockets.org/git/libwebsockets/tree/minimal-examples/secure-streams/minimal-secure-streams-staticpolicy/static-policy.h

Using this technique it's possible to standardize on maintaining JSON policies across a
range of devices with different contraints, and use the C conversion of the policy on devices
that are too small.

The Cmake option `LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY` should be enabled to use this
mode, it will not build the JSON parser (and the option for LEJP can also be disabled if
you're not otherwise using it, saving an additional couple of KB).

Notice policy2c example tool must be built with `LWS_ROLE_H1`, `LWS_ROLE_H2`, `LWS_ROLE_WS`
and `LWS_ROLE_MQTT` enabled so it can handle any kind of policy.

## HTTP and ws serving

All ws servers start out as http servers... for that reason ws serving is
handled as part of http serving, if you give the `ws_subprotocol` entry to the
streamtype additionally, the server will also accept upgrades to ws.

To help the user code understand if the upgrade occurred, there's a special
state `LWSSSCS_SERVER_UPGRADE`, so subsequent rx and tx can be understood to
have come from the upgraded protocol.  To allow separation of rx and tx
handling between http and ws, there's a ss api `lws_ss_change_handlers()`
which allows dynamically setting SS handlers.

Since the http and ws upgrade identity is encapsulated in one streamtype, the
user object for the server streamtype should contain related user data for both
http and ws underlying protocol identity.
