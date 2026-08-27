# lws minimal ws server + permessage-deflate for bulk traffic

## build

```
 $ cmake . && make
```

## usage

```
 $ ./lws-minimal-ws-server-pmd-bulk
```

 - `-n` disable permessage-deflate extension
 - `-c` send compressible text instead of uncompressible binary data
 - `-b` send the whole message as a single blob, instead of in fragments
 - `--port <port>` listen on a different port (default 7681)

Visit http://localhost:7681 in your browser

One or another kind of bulk ws transfer is made to the browser.

The ws connection is made via permessage-deflate extension.
