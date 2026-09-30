# lws-api-test-ss-multipart

Confirms how a Secure Streams client whose streamtype has
`"http_multipart_ss_in": true` deframes a multipart response body into one
`LWSSS_FLAG_SOM` .. `LWSSS_FLAG_EOM` message per part (the part's own headers
included), bracketed by zero-length `LWSSS_FLAG_RELATED_START` and
`LWSSS_FLAG_RELATED_END` messages, however the server splits the body.

A raw socket server in the same process answers each GET with a canned
HTTP/1.1 response sent with chunked transfer encoding.  Each chunk reaches the
client's multipart parser as a separate piece, so the test chooses exactly
where the pieces begin and end.  The phases are fetched one after the other on
the same client stream:

|phase|what it checks|
|---|---|
|crlf-split|a part's chunk ends in the CRLF starting the next delimiter, the next chunk is exactly the rest of the delimiter line; a chunk ends in a lone CR; the preamble is discarded|
|boundary-chunks|the body starts with a chunk that is exactly the first delimiter line; an empty part; transport padding after a delimiter; the start of a delimiter at the end of a chunk that turns out to be content; an epilogue|
|not-multipart|a later non-multipart response on the same stream is passed through untouched|
|one-chunk|a whole multipart body in a single chunk|

The client checks each part's content exactly, that no message claims more
data than fits a part, and the RELATED_START / RELATED_END counts.

## Switches

|Option|Meaning|
|---|---|
|-p <port>|Port for the in-process test server (default 7681)|
|--server <address>|Address the client connects to (default localhost)|
|--help|Show the options|

## Run

```
$ ctest -R api-test-ss-multipart
```
