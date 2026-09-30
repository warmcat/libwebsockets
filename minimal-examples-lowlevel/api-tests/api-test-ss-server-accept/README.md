# lws-api-test-ss-server-accept

Confirms the lifetime of the streams a Secure Streams server accepts.

Every connection that arrives at a Secure Streams server, and every h2 stream
on one, gets an accepted stream of its own, created from the server
("template") stream the user code made.  Whatever the peer does, the accepted
stream must be destroyed when its connection goes, or the server keeps one
stream object for every connection it ever saw, until the context is
destroyed.

The policy describes a tls server streamtype `accsrv`.  The user code counts
each accepted stream's `LWSSSCS_CREATING` and `LWSSSCS_DESTROYING`, so it knows
how many are alive.  A client in the same process runs each phase three
times; after each run, every accepted stream the server made for it must have
been destroyed.

|phase|client|
|---|---|
|tcp|connects and closes, without starting tls|
|h1-partial|tls with ALPN http/1.1, sends part of a request header and closes|
|h1-txn|a complete http/1.1 GET, the server answers|
|h2-txn|a complete h2 GET, the server answers: the h2 network connection has an accepted stream of its own besides the one for the request's stream|

## Switches

|Option|Meaning|
|---|---|
|-c <path>|Path to the JSON policy to use (required; ctest passes the generated one)|
|-p <port>|Port the client connects to, must be the policy's server port (default 7681)|
|--server <address>|Address the client connects to (default 127.0.0.1)|
|--help|Show the options|

## Run

```
$ ctest -R api-test-ss-server-accept
```
