# lws minimal http client multi

## build

```
 $ cmake . && make
```

## usage

The application goes to https://warmcat.com and receives the page data
same as minimal http client.

However it does it for 8 client connections concurrently.

## Commandline Options

Option|Meaning
---|---
-s|Stagger the connections by 100ms, the last by 1s
-p|Use http/1.1 pipelining or h2 simultaneous streams
--h1|Force http/1 only
-l|Connect to server on https://localhost:7681 instead of https://warmcat.com:443
-n|Read numbered files like /1.png, /2.png etc.  Default is just read /
--uv|Use libuv event loop if lws built for it
--event|Use libevent event loop if lws built for it
--ev|Use libev event loop if lws built for it
--post|POST to the server rather than GET (a multipart body of unknown length: over http/1.1 lws sends it chunked)
-c<n>|Create n connections (n can be 1 .. 8)
--path <path>|Force the URL path (should start with /)
--save-ticket <path>|After the run, save the client's tls session for the first URL's host and port to the file.  With `--h3` it is the quic session, else the tls over tcp one
--load-ticket <path>|Before connecting, load a tls session saved by `--save-ticket` into the client's session cache, so the first connection resumes it.  With `--h3` and `--0rtt`, the requests are sent as 0-RTT early data