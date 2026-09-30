# lws api test html process

`lws_chunked_html_process()` replaces variables in a file being interpreted,
one lump of the file at a time, in place, and frames each lump as an h1 chunk
when asked.  Where the file is cut into lumps is not the interpreter's choice
(on h2 the peer's flow control window decides it), so a variable can be split
across two lumps.

The test feeds a small page through it cut into lumps of every size from one
byte to the whole page, chunked and not, laid out as `lws_http_file_tx()`
lays them out: 10 bytes in front of the lump for the chunk size line, 128
after it to grow into.  For every cut:

 - the output, with the chunk framing checked and taken off, is the page with
   its variables replaced, including ones split across lumps, and a partial
   variable at the very end left as text
 - a lump held back whole produces nothing, not an empty chunk, which would
   end the body, and the last one ends with the last-chunk
 - nothing is written outside the buffer

It also checks a substitution with no room to grow into is refused without
writing past the buffer, and that a last lump that comes to nothing is just
the last-chunk.

## running it

```
$ ./lws-api-test-html-process
```
