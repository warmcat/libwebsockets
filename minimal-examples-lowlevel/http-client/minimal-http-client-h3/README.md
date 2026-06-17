# lws-minimal-http-client-h3

This demonstrates a minimal HTTP/3 (QUIC) ONLY client using libwebsockets.

It fetches `https://libwebsockets.org/index.html` exclusively over HTTP/3, and exits with a success or failure status code based on if it could fetch the page.

## Build

```bash
 $ cmake . && make
```

## Usage

```bash
 $ ./lws-minimal-http-client-h3
```
