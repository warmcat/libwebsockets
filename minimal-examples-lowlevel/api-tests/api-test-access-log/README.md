# lws-api-test-access-log

Checks that a vhost's access log is one line per request, whatever the peer
sends in it.

A raw client sends GETs to an http vhost writing an access log
(`log_filepath`), each on its own connection:

 - with a 400-byte Referer and a User-Agent of every length from 1 to 700
   bytes, so that some request fills the line exactly, whatever the length
   of the rest of it,
 - with a Referer, a User-Agent, or both much too long for the line,
 - with an empty Referer and User-Agent,
 - with quotes, tabs and DEL in the Referer and User-Agent,
 - with a backslash ending the URI, Referer and User-Agent,
 - with bytes above 0x7f (UTF-8, including U+009B CSI, and a raw 0x9b CSI)
   in the URI, Referer and User-Agent,
 - with a Referer and User-Agent that are much too long for the line once
   escaped,
 - with a URI longer than the log keeps, plain and escaped.

Once the context has closed the log, every line must end with a newline and
contain nothing but printable ASCII, so it can never run into the next one
or act on a terminal; contain exactly the six quotes around the request,
referrer and user agent, after a host field with no spaces, with every
backslash in those fields starting an escape (`\\` or `\xhh`), so that a
reader honouring escapes, as Apache's log format has them, finds the same
fields; and have the request, referrer and user agent that were sent, with
quotes replaced by `'` and C0 control characters by `_`, backslashes doubled
and DEL and bytes above it written `\xhh`, cut short only when the line
could not hold them, never inside an escape, and then each keeping a fair
share.  There must be exactly one line per request.

## Commandline

| option | meaning |
|--------|---------|
| `--server ADDRESS` | where the server is reached, default `localhost` |
| `--access-log FILE` | the server's access log, emptied first, checked at the end |

## Run

```
$ ctest -R api-test-access-log
```
