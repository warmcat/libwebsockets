# lws-api-test-tls-accept-async

An lws tls server and a burst of lws clients in one process confirm that every
connection is served, however its tls accept was done.

With `LWS_WITH_ASYNC_QUEUE` and `LWS_MAX_SMP` > 1, a server's tls accept steps
go to a worker thread, whose queue holds ten jobs per worker.  The poll set
takes nothing for the connection while its step is out on the worker.  When
the queue is full, the step is done inline on the service thread instead, and
that step can be the one completing the handshake, with the client's request
already sent behind its Finished.  The connection must be reading again then,
or the request waits unread for the connection's timeout.

The clients make `--count` concurrent connections at once, alternately h1 and
h2, each a GET that the server answers with a short body.  Every one must
complete with a 200 and the whole body within 20s.

|ctest|What|
|---|---|
|`api-test-tls-accept-async`|The burst races the single worker: some accepts may go to it, and some may find its queue full and be done inline|
|`api-test-tls-accept-async-queue-full`|With `LWS_WITH_SYS_FAULT_INJECTION`, the context fault `async_queue_full` makes every accept find the queue full, so each is done inline|

In builds without the async queue, or with `LWS_MAX_SMP` 1, every accept is
inline anyway, and the test checks that all connections are served.

The server uses `api-test-ws-close`'s `localhost-100y` test certificate, and
the clients accept it as self-signed.

## Running it

```
$ lws-api-test-tls-accept-async -p 7681 --certs ../api-test-ws-close
$ lws-api-test-tls-accept-async -p 7681 --certs ../api-test-ws-close --fault-injection async_queue_full
```

|Option|Meaning|
|---|---|
|`-p <port>`|Port of the tls server vhost (default 7681)|
|`-s <address>`|Address the clients connect to (default `localhost`)|
|`--certs <dir>`|Dir holding `localhost-100y.cert` and `.key` (default `.`)|
|`--count <n>`|How many connections to make at once, 1 to 64 (default 24)|
|`--fault-injection async_queue_full`|Every async queue submission is refused as if the queue were full (needs `LWS_WITH_SYS_FAULT_INJECTION`)|
