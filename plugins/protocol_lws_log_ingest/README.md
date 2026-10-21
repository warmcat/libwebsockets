# lws-log-ingest

Keeps the log lines of many log shippers, processes on other machines using
`lws_log_ship_create()` or an `"lws-log-ship"` ws-protocols config, in one sqlite db
in UTC, and gives them the windows of time to send lines for from the sessions
someone starts.  It answers a JSON api for the sessions and their lines, and
its assets are a page for looking at them, every source side by side at one
instant.

See [READMEs/README.log-ship.md](../../READMEs/README.log-ship.md) for how it
works, its config, the wire protocol and the api.

 - `protocol_lws_log_ingest.c`: the shippers' connections, and sessions
 - `ingest-store.c`: the db
 - `ingest-api.c`: the http api
 - `assets/`: the viewer
