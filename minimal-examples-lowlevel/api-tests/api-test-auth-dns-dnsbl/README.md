# lws-api-test-auth-dns-dnsbl

Fence for security-audit finding F-054: pending DNSBL query lifetimes in the
authoritative-DNS plugin (`protocol-lws-auth-dns`).

The test builds the plugin in statically, serves a small zone with the `dnsbl`
pvo configured, and pins the whole context async resolver to a local UDP stub
that captures the DNSBL lookups but only answers them after the plugin's 5s
DNSBL timeout has already replayed the suspended answer and freed the pending
query.

| leg | what it does | pre-fix behavior | post-fix behavior |
|-----|--------------|------------------|-------------------|
| 1 | UDP query for a served A record; resolver replies are deliberately late | late reply completes a resolver query whose opaque is freed heap -> `dnsbl_query_cb()` UAF (ASAN red) | lookups cancelled when the query is freed; late replies dropped as unknown tids |
| 2 | TCP client disconnects while its query is suspended on DNSBL lookups | `q->wsi` dangles into the closed wsi; the 5s timeout replays into it (ASAN red) | `RAW_CLOSE` sweep NULLs `q->wsi`; the timeout skips the replay |

The test asserts the DNSBL path engaged (the stub saw lookups), the suspended
UDP answer really arrived via the 5s timeout replay, and both legs' late
replies were serviced harmlessly before the test ends.

## Commandline

| option | meaning |
|--------|---------|
| `-p PORT` | port for the auth dns UDP + TCP listeners (from `lws_get_free_port()`) |
| `-b PORT` | port for the blackholed DNSBL resolver stub (from `lws_get_free_port()`) |
| `-z DIR` | zone dir to serve (default `zones-dnsbl`) |

Because the stub only answers at 7s (after both 5s plugin timeouts), the test
takes around 10s.
