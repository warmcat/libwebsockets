# lws minimal http client POST

This example demonstrates a multipart POST to

https://libwebsockets.org/testserver/formtest

setting both a form variable and uploading a
short file.

The result of the POST form processing is captured
and displayed in a hexdump.

This is programmatically POSTing to the same
form you can access at

https://libwebsockets.org/testserver

in the "POST" tab with file upload.

By default the client action occurs using http/2 if
your lws was built with `-DLWS_WITH_HTTP2=1`.

## build

```
 $ cmake . && make
```

## usage

```
$ echo "https://libwebsockets.org/testserver/formtest --form text=mytext --form file=@libwebsockets.pc" | ./bin/lws-minimal-http-client-post-form
```

Each `--form` element must be shorter than the 4095 characters
lws_http_mp_sm has room for: a longer one, or a file that changes size
between the Content-Length being computed and its contents being sent,
fails the request rather than sending a body of a different length.
