# lws api test deaddrop

Drives the `lws-deaddrop` plugin, built into the test with
`LWS_PLUGIN_STATIC`, over http and ws in one process, as two basic auth users
whose names share a prefix, `bob` and `bob_smith`.

|step|expected|
|---|---|
|`bob_smith` uploads `notes.txt`, then `bob` uploads `smith_notes.txt`|both 200, two separate files|
|30 ws sessions as `bob_smith`, one as `bob`, with a legacy `bob_legacy.txt` already in the upload dir|every session gets well-formed, correctly framed listings that settle on all 31 users and 3 files, each file "yours" only to its uploader, and the legacy file still `bob`'s|
|`bob` sends `{"del":"<bob_smith's file>"}`|refused, the file stays|
|`bob` sends a message that leaves `"}` in the server's rx buffer, then `{"del":"<his file>` with no closing quote, then short `del` frames|all ignored, nothing deleted|
|`bob` deletes his own file|deleted, and every session's listing drops it|
|`bob` uploads `x.html`, `x.svg`, `x.js`; `bob_smith` fetches them from `/get/`|each 200, `application/octet-stream`, `Content-Disposition: attachment` naming the file, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: sandbox; default-src 'none'`, the content intact|
|`bob_smith` fetches a name that does not exist|404|

## running it

```
$ ./bin/lws-api-test-deaddrop --server localhost -p 7681 \
	--upload-dir /tmp/dd-upload --passwords ./ba-passwords
```

|option|meaning|
|---|---|
|`-p <port>`|port for the deaddrop server vhost|
|`--server <addr>`|address the clients connect to|
|`--upload-dir <dir>`|upload dir; created if needed and emptied of files first|
|`--passwords <file>`|basic auth login file (`./ba-passwords` here)|
