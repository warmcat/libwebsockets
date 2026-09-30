# lws-api-test-ss-server-txn

Confirms what the metadata of a Secure Streams http server stream holds when
the user code hears `LWSSSCS_SERVER_TXN`, for requests arriving one after the
other on the same keep-alive h1 connection, and so on the same accepted stream.

The policy's server streamtype declares `"mime": "Content-Type:"` (emitted as a
response header), `"path"`, `"method"`, `"auth"` and a plain `"my_arg"`.  A raw
socket client in the same process sends each request after the previous
response completed.  The streamtype also serves the ws subprotocol `txn-ws`.

|txn|request|the server stream must see|
|---|---|---|
|urlargs|`/txn/one?path=/admin&method=POST&auth=...&mime=text/evil&my_arg=hello` with `Authorization: Bearer real`|path `/txn/one`, method `GET`, auth `Bearer real`, my_arg `hello`, mime not from the request|
|plain|`/txn/two`, no Authorization, no URL args|path `/txn/two`, method `GET`, auth and my_arg unset|
|upgrade|a ws upgrade to the policy's `ws_subprotocol` on the same connection|`LWSSSCS_SERVER_UPGRADE` after the earlier `LWSSSCS_SERVER_TXN`s, and the client gets the 101|

## Switches

|Option|Meaning|
|---|---|
|-p <port>|Port for the in-process test server (default 7681)|
|--server <address>|Address the client connects to (default localhost)|
|--help|Show the options|

## Run

```
$ ctest -R api-test-ss-server-txn
```
