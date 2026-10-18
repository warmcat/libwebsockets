# lws-api-test-lhp-doc-cache

Selftest for lhp's document asset cache against what a server sends, through
`lws_lhp_ss_browse()`.  The cache keeps a copy of each document and stylesheet
payload as it arrives, to write it through at the end; the parsers stream, so
that copy is the only thing holding the whole payload, and the server decides
how big it is.

A plain http server vhost and the browse run in the same process, with a JSON
policy whose `__default` streamtype allows plain http (the built-in one is
tls-only).  It fences that:

 - a small page and its small stylesheet are laid out and cached, so the
   cache is known to work;

 - a page bigger than `LWS_DLO_ASSET_BLOB_MAX_PAYLOAD` is laid out but not
   cached;

 - a small page linking a stylesheet bigger than that is cached, the
   stylesheet not;

 - the url passed to `lws_lhp_ss_browse()` only needs to last for the call:
   the test scribbles on it afterwards, and the server drops the first
   connection so the fetch has to connect again from it.

Options:

| Option | Meaning |
|---|---|
| `--server <addr>` | address the server is reached at (default `127.0.0.1`) |
| `--tmpdir <dir>` | where the scratch asset cache is made (default `.`) |

ctest passes `--server ${LWS_CTEST_SERVER_RESOLVE}` and its binary dir as
`--tmpdir`.  The scratch cache is removed at exit.

Run via ctest from a build with `-DLWS_WITH_MINIMAL_EXAMPLES=1`.
