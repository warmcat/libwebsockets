# lws-api-test-client-no-vhost

A client connection given no vhost in its connect info goes on the "default"
vhost, else the first vhost that isn't lws's own "system" one.  In a context
with `LWS_SERVER_OPTION_EXPLICIT_VHOSTS` (which `lws_context_info_defaults()`
sets) where the app has created no vhost, there is none, and
`lws_client_connect_via_info()` must return NULL cleanly, freeing the wsi it
began (G-694).

Where lws's own protocols (eg, async dns, stdin) need one, as on any
networked unix or windows build, the context has a "system" vhost and it is
the only one; elsewhere there is no vhost at all.  The test logs which.

|step|expected|
|---|---|
|http GET, no vhost|refused (NULL)|
|tls GET, no vhost (TLS builds)|refused (NULL)|
|ws upgrade, no vhost (ws builds)|refused (NULL)|
|the app creates a vhost, http GET to a port nothing listens on|taken, then one `LWS_CALLBACK_CLIENT_CONNECTION_ERROR`|

Run it under ASan, with and without `LWS_WITH_SYS_FAULT_INJECTION`: before
the fix, a fault injection build dereferenced the NULL vhost to inherit its
faults.

## Switches

|Option|Meaning|
|---|---|
|--port <port>|A port nothing listens on, for the connection that is taken (default 7681)|
|--server <address>|Address the clients connect to (default localhost)|
|--help|Show the options|

## Run

```
$ ctest -R api-test-client-no-vhost
```
