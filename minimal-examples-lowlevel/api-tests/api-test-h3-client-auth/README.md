# lws api test h3 client auth

What the h3 client sends with a request besides what the caller asked for:
the answer to a digest challenge, and the cookies from its jar.  The h1 and
h2 clients always sent both; the h3 client's request composer sent neither.

An h3 server and the h3 client are in the same process, on h3 only, with no
fallback to tcp.

 - `--case digest`: the client has credentials, and GETs `/digest`, answered
   401 with a digest challenge unless it carries a digest `Authorization`.
   It must end 200.
 - `--case cookie`: the client keeps cookies.  It GETs `/set`, answered with
   a Secure cookie, then makes a new connection to GET `/check`, which
   answers with the `Cookie` it came with.  It must be the cookie.

```
$ ./lws-api-test-h3-client-auth --case digest -p 7790 \
	--cert localhost-100y.cert --key localhost-100y.key
```

Option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d15
-p <port>|The server's port (default 7790)
--case digest\|cookie|Which case to run
--cert <file>, --key <file>|The server's cert and key
--jar <file>|The client's cookie jar (default ./h3-client-auth-jar.txt), emptied first
