# lws-api-test-ss-server-accept

Confirms the lifetime of the streams a Secure Streams server accepts.

Every connection that arrives at a Secure Streams server, and every h2 stream
on one, gets an accepted stream of its own, created from the server
("template") stream the user code made.  Whatever the peer does, the accepted
stream must be destroyed when its connection goes, or the server keeps one
stream object for every connection it ever saw, until the context is
destroyed.

The policy describes three server streamtypes: `accsrv` (http over tls),
`accplain` (http without tls) and `accraw` (raw).  The user code counts each
accepted stream's `LWSSSCS_CREATING` and `LWSSSCS_DESTROYING`, so it knows how
many are alive.  A client in the same process runs each phase three times;
after each run, every accepted stream the server made for it must have been
destroyed.

In the "refused" phases the user code returns `LWSSSSRET_DESTROY_ME` from an
accepted stream's `LWSSSCS_CREATING`: the connection (or for h2, the stream)
must be closed cleanly, freed once, with no accepted stream left.

|phase|server|client|
|---|---|---|
|tcp|tls|connects and closes, without starting tls|
|plain-txn|plaintext|a complete http/1.1 GET, the server answers|
|plain-refused|plaintext|a GET; the server refuses the connection's accepted stream|
|raw|raw|connects and closes|
|raw-refused|raw|connects; the server refuses the connection's accepted stream|
|h1-partial|tls|ALPN http/1.1, sends part of a request header and closes|
|h1-txn|tls|a complete http/1.1 GET, the server answers|
|h1-refused|tls|a GET; the server refuses the connection's accepted stream|
|h2-txn|tls|a complete h2 GET, the server answers: the h2 network connection has an accepted stream of its own besides the one for the request's stream|
|h2-refused|tls|an h2 GET; the server accepts the connection's stream and refuses the request stream's|
|server-gone|plaintext|connects, sends part of a request and stays; the user code destroys the server stream, which must take the connection and its accepted stream with it (once, the server is gone after)|

## Switches

|Option|Meaning|
|---|---|
|-c <path>|Path to the JSON policy to use (required; ctest passes the generated one)|
|-p <port>|Port of the policy's tls server (default 7681)|
|--port-plain <port>|Port of the policy's plaintext server (default 7682)|
|--port-raw <port>|Port of the policy's raw server (default 7683)|
|--server <address>|Address the client connects to (default 127.0.0.1)|
|--help|Show the options|

## Run

```
$ ctest -R api-test-ss-server-accept
```
