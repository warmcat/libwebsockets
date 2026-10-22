# lws-api-test-ota

Runs `lws_ota` against a fake platform OTA layer (the `lws_ota_ops_t` a real
platform, like esp32, provides) and a raw socket http server in the same
process, and confirms that however an update ends, `lws_ota` leaves the
platform, the system state and the periodic update checks the way they should
be.

The fake platform completes its ops later from a timer, as a real platform
completes them from its own task, and reads `g->buf` only when a flash write
completes, like a write that is in flight elsewhere.  It flags any op queued
while another is in flight, or after `ABORT` or `FINALIZE`.

|case|what happens|what is checked|
|---|---|---|
|complete|the whole image is served|every byte reaches the platform with the right hash, `FINALIZE` and `reboot()`|
|cut|the server closes partway through the image|the platform op is aborted as soon as the buffered data runs out, not after the 45s drain timeout|
|stall-timeout|the server holds the connection partway through, and the stream times out while a flash write is in flight|the `lws_ota_t` outlives the write, then `ABORT` is queued and acknowledged|
|refuse-modal|user code refuses to enter `LWS_SYSTATE_MODAL_UPDATING` until `lws_ota` gives up|the platform is never started|
|context-destroy|the context is destroyed while a flash write is in flight|`ota_detach()` makes the platform let go before the `lws_ota_t` is freed|

After each of the first four, the system state must be back at
`LWS_SYSTATE_OPERATIONAL`, the periodic update check scheduled, and the
platform holding nothing.

## Building

The test signs its update manifest at runtime with `ota-test.private.jwk`, so
`lws_ota` can only accept it if lws was built to trust the public half.  It is
only built when lws is configured with

```
-DLWS_WITH_OTA=1 -DLWS_OTA_VARIANT=lws-api-test-ota \
-DLWS_OTA_PUBLIC_JWK_FILE=<lws>/minimal-examples-lowlevel/api-tests/api-test-ota/ota-test.public.jwk
```

(any variant name works).  `LWS_OTA_PUBLIC_JWK_FILE` is pasted into a C string,
so the public key file holds the JWK with its quotes escaped.  The key pair is
for this test only and is not secret.

The fake platform needs the layout of the private `struct lws_ota`, as the
platform implementations inside lws do, so the test only builds inside the lws
build tree.

## Switches

|Option|Meaning|
|---|---|
|-p <port>|Port for the in-process update server (default 7681)|
|--server <address>|Address the client connects to (default localhost)|
|--help|Show the options|

## Run

```
$ ctest -R api-test-ota
```
