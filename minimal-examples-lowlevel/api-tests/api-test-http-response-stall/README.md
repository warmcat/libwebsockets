# lws-api-test-http-response-stall

A response that is still going must be bounded by how long it stalls, not how
long it takes, and the stall it is allowed is the vhost's
`http_response_stall_secs` (lwsws `http-response-stall-secs`).

The file sender used to arm the content timeout, `timeout_secs`, for each
piece of a file it sent, overriding the response watchdog the headers armed.
So a peer that stopped reading a big download for longer than `timeout_secs`
(15s by default), eg, a browser draining its cache to a slow device, had it
cut off, with nothing logged above info level.

The server vhost here serves a 64MB file, far bigger than loopback's socket
buffers, with a `timeout_secs` of 2s and an `http_response_stall_secs` of 6s.
The client reads 1MB of it, stops reading with rx flow control, then resumes:

 - after 4s, longer than `timeout_secs`, it must get the whole file;
 - after 10s, longer than `http_response_stall_secs`, the server must have
   given up on it, so it gets less.

## Running

The test is registered with ctest as `api-test-http-response-stall`; it
obtains a free listen port at configure time and passes it via `-p`.

```
$ ctest -R api-test-http-response-stall
```
