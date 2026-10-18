# lws api test ss redirect

A Secure Streams client whose policy allows redirects (`allow_redirects`) sends
what its policy and metadata put in its headers again to wherever a redirect
takes it.  So a stream carrying credentials in them (here the device serial,
as `x-dsn:` from `http_dsn_header`, or an api key in a metadata-bound
`x-api-key:`) follows a redirect only over https with strict verification, to
the host it started with or a subdomain of it, or to a host its policy's
`redirect_credentials_to` names.  Otherwise the redirect is refused, however
it is spelled:

 - a relative path, an absolute URI naming our host, and a network-path
   reference (`//host:port/path`) naming our host are followed
 - an absolute URI, or a network-path reference, naming another host is
   refused: `//host/path` is not a path, it names another authority as much
   as `https://host/path` does
 - our own host, but over http, is refused
 - another host the policy names in `redirect_credentials_to` is followed
 - a stream carrying no credentials, only an ordinary header (`accept:` from
   metadata), follows a redirect to another host

A small raw socket server in the same process, over tls and on a plaintext
port, answers `/start/<phase>` with that phase's redirect, and anything else
with a 200, noting what it was asked for.  Each phase is a stream of its own,
with no retries.  The other host is another name for the same server
(`127.0.0.1` when the policy says `localhost`), which its certificate is also
valid for, so a redirect to it that was followed would reach the server, and
be seen.

```
$ ./lws-api-test-ss-redirect -p 7681 --port-plain 7682 \
	--cert ../api-test-ws-close/localhost-100y.cert \
	--key ../api-test-ws-close/localhost-100y.key
```

Option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d15
-p <port>|Port for the tls test server (default 7681)
--port-plain <port>|Port for the plaintext test server (default 7682)
--cert <file>|The test server's certificate (default localhost-100y.cert)
--key <file>|The test server's key (default localhost-100y.key)
--server <address>|Address the client connects to (default localhost)
--help|Show the options
