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
The client reads 1MB of it and stops reading with rx flow control:

 - resuming after 4s, longer than `timeout_secs`, it must get the whole file;
 - not resuming, the server must give up on it, but no sooner than
   `http_response_stall_secs` after it stopped.  The client, not reading,
   can't see that, so the server's side of the test tells it, and it resumes
   to find the file cut off.  It fails if the server has not given up 30s
   after the client stopped.

The server's stall counts from the last it sent, and what the client read
last before it stopped was sent a little before that, so the server can give
up a few ms short of `http_response_stall_secs` after the client stopped: the
test allows it to be 500ms short, still far past the `timeout_secs` cut the
file sender used to make.

A peer that stops reading may still take a little more, which renews the
watchdog: on the BSDs and macOS, the sender's persist timer probes the closed
window after 5s, and the receiver opens it for the room it had held back from
advertising, less than a segment.  So there the server gives up about 11s
after the client stopped, and on Linux, 6s.

A second server vhost, with an `http_response_stall_secs` of 2s, answers with
the whole of a 1.5MB response in one write.  The socket buffers on both sides
are made small, so most of it waits in lws to be sent, and the client takes
it slowly, stopping for 150ms in each 64KB, so it takes far longer than 2s to
go.  It must get all of it: lws sending more of what it had waiting is
progress, and renews the watchdog as much as the write did.

## Running

The test is registered with ctest as `api-test-http-response-stall`; it
obtains two adjacent free listen ports at configure time and passes the
first via `-p`: the file's vhost listens on it, the big write's on the next.

```
$ ctest -R api-test-http-response-stall
```
