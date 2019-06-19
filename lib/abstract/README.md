# Abstract protocols and transports

## Overview

Until now protocol implementations in lws have been done directly
to the network-related apis inside lws.

In an effort to separate out completely network implementation
details from protocol specification, lws now supports
"abstract protocols" and "abstract transports".

![lws_abstract overview](/doc-assets/abstract-overview.svg)

The concept is that the abstract protocol implementation only
operates on callback events and reads and writes to buffers...
separately when it is instantiated, it can be bound to an
"abstract transport" which handles all the details of sending
and receiving on whatever the transport is.

This makes it possible to confidently offer the same protocol on
completely different transports, eg, like serial, or to wire
up the protocol implementation to a test jig sending canned
test vectors and confirming the response at buffer level, without
any network.  The abstract protocol itself has no relationship
to the transport at all and is completely unchanged by changes
to the transport.

lws SMTP client support has been rewritten to use the new scheme,
and lws provides a raw socket transport built-in.

## Public API

The public api for defining abstract protocols and transports is
found at [transports.h](https://libwebsockets.org/git/libwebsockets/tree/include/libwebsockets/abstract/transports.h)

### `lws_abstract_t`

The main structure that defines the abstraction is `lws_abstract_t`,
this is a name and then about a dozen function pointers for various
events and operations.

The transport defines about half of these and exports this
`lws_abstract_t *` via its name, it can be retreived using

```
LWS_VISIBLE LWS_EXTERN const lws_abstract_t *
lws_abstract_get_by_name(const char *name);
```

At the moment only "`raw-skt`" is defined as an lws built-in, athough
you can also create your own mock transport the same way for creating
test jigs.

|transport op|meaning|
|---|---|
|`tx()`|transmit a buffer|
|`client_conn()`|start a connection to a peer|
|`close()`|request to close the connection to a peer|
|`ask_for_writeable()`|request a `writeable()` callback when tx can be used|
|`set_timeout()`|set a timeout that will close the connection if reached|
|`state()`|check if the connection is established and can carry traffic|

These are called by the protocol to get things done and make queries
through the abstract transport.

When you instantiate an abstract protocol, it defines the other half of
the `lws_abstract_t` operations and is combined with the transport
`lws_abstract_t *` to get the full set of operations necessary for the
protocol to operate on the transport.

|protocol op|meaning|
|---|---|
|`accept()`|The peer has accepted the transport connection|
|`rx()`|The peer has sent us some payload|
|`writeable()`|The connection to the peer can take more tx|
|`closed()`|The connection to the peer has closed|
|`heartbeat()`|Called periodically even when no network events|

These are called by the transport to inform the protocol of events
and traffic.

### `lws_token_map_t`

The abstract protocol has no idea about a network or network addresses
or ports or whatever... it may not even be hooked up to one.

If the transport it is bound to wants things like that, they are passed
in using an array of `lws_token_map_t` at instantiation time.

For example this is passed to the raw socket protocol in the smtp client
minimal example to control where it would connect to:

```
static const lws_token_map_t smtp_abs_tokens[] = {
{
	.u = { .value = "127.0.0.1" },
	.name_index = LTMI_PEER_DNS_ADDRESS,
}, {
	.u = { .lvalue = 25l },
	.name_index = LTMI_PEER_PORT,
}};
```

