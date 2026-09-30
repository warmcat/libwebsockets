# lws api test lws_spa

Checks what `lws_spa` makes of POSTed forms, in one process.

An h1 server has two callback mounts that parse every POSTed form with
`lws_spa` and answer with what it made of it: each parameter it was asked for
as `name=NULL` when the form did not have it, else `name='value'/length`, and
what its file upload callback saw (opens, ends, bytes, and whether they
came in order).  `/form` keeps the values in the spa's own
storage, `/form-ac` in an lwsac.  A GET to either is answered `get`.

A raw client sends each case's request bytes on a connection of its own and
checks the answers.  A case can hold back the end of its body and send it,
with anything pipelined after it, after a pause, so the server sees the body
in two reads.

## what is covered

|form|expected|
|---|---|
|urlencoded `a=1&b=two&c=x%20y+z`|the decoded values|
|urlencoded `a&b=1&c`|`a` and `c` present with empty values|
|urlencoded `a=&b=1&c=`|the same|
|multipart fields|the part contents|
|multipart, two file parts around a field|the upload callback hears each file open once, before its content, and end once|
|multipart, a part header the spa does not know, with dashes in it|skipped, the form goes on|
|multipart with an epilogue after the close delimiter, then a pipelined GET, the epilogue in the same read or held back, with a Content-Length or chunked|the form, then the GET answered as itself|
|multipart with neither a Content-Length nor chunked|the close delimiter ends the body|

The urlencoded cases run against both kinds of storage.

## running it

```
$ ./bin/lws-api-test-lws_spa -p 7681
```

`--only <text>` runs just the cases whose name contains it.
