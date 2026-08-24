# Notes on http parser corner cases

## Dealing with control bytes in the URI

Any C0 control byte (< 0x20) or DEL (0x7F) is forbidden in the request URI
-- in the path part and in urlargs, whether the byte appears raw on the wire
or percent-encoded (%00, %01, %0D, %0A, %7F ...).  The request is refused
with 403 on h1, and a connection error on h2/h3 :path.

Historically %00 was allowed in the *value* part of a urlarg ("retrieval
with explicit length"), but user code overwhelmingly treats urlarg values
as NUL-terminated strings, so the allowed-NUL contract was unusable in
practice and has been withdrawn.  Decoded CR/LF in a urlarg also used to
truncate the value and silently skip the rest of the request line; such
requests are now refused outright.

Spaces (from `%20` or `+`) and bytes >= 0x80 (UTF-8) are unaffected.

## Note on proper urlarg handling

Although urlarg values can no longer contain NUL or other control bytes,
they are not NUL-terminated in the ah storage, so it is still important to
use the length-based urlarg apis

 - `lws_hdr_copy_fragment()`
 - `lws_get_urlarg_by_name_safe()`

The non-length based urlarg api

 - `lws_get_urlarg_by_name()`

...is soft-deprecated, it's still allowed but it may truncate at unexpected
places.  Use `lws_get_urlarg_by_name_safe()` instead.
