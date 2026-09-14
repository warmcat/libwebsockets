# lws api test h2 post bind

Checks the protocol callback ordering for requests served by the default
protocol fallback on a vhost with no mounts, for every role and method: the
protocol must see `LWS_CALLBACK_HTTP_BIND_PROTOCOL` (with the per-session
allocation to initialize) before `LWS_CALLBACK_HTTP`, and the matching
`LWS_CALLBACK_HTTP_DROP_PROTOCOL` when the transaction is over.

HTTP/2 POST requests are dispatched by the h2 role itself rather than by
`lws_http_action()`; a regression on that path skipped the bind for the
no-mount case, so the app got `LWS_CALLBACK_HTTP` on a per-session area no
callback had had the chance to initialize, and never saw the drop either.

Four legs, each a single request from an lws client in the same process to a
mountless vhost: h1 GET, h1 POST, h2 GET, h2 POST (cleartext, prior knowledge).
A leg fails unless the server protocol saw exactly
bind -> http [-> body... -> body completion] -> drop on one and the same
per-session pointer, with a marker set at the bind still intact when
`LWS_CALLBACK_HTTP` ran.

```
$ ./lws-api-test-h2-post-bind -p 7681 --h2-port 7682
```

Option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d1151
-p <port>|Port for the h1 server vhost (default 7681)
--h2-port <port>|Port for the h2 prior-knowledge server vhost (default 7682)
--server <addr>|Server address to connect to (default 127.0.0.1)
