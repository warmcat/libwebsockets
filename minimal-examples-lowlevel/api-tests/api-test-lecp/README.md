# lws api test lecp

Selftests for the lws CBOR parser (lecp) and writer (lws_lec_*).

The parse side runs the RFC 8949 example vectors and the lws regression
vectors through the streaming parser, one byte at a time as well as whole,
and checks the callback sequence, paths, indexes and values.  A structural
conformance checker confirms that START / END events pair up, that array
items and tags bracket exactly one item each, and that map keys and values
alternate, for every positive vector.

Map keys go into `ctx->path` as they are: the map key vectors check that a
text or byte string key containing a NUL is always rejected with
`LECP_REJECT_BAD_CODING`, and that `{"a.b": 1}` matches the path `.a.b` just
as `{"a": {"b": 1}}` does, the aliasing documented at `lecp_construct()`.

The write side renders the same documents through `lws_lec_printf()` into
output windows of every size from 1 to 80 bytes and checks the concatenated
result matches the one-shot output, covering the resumable scratch and
argument handling.

## build

```
 $ cmake . && make
```

## usage

Commandline option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d15
--help|Show the options

```
 $ ./lws-api-test-lecp
[2026/09/30 16:10:11:2529] U: LWS API selftest: LECP CBOR parser
...
[2026/09/30 16:10:11:2982] U: Completed: PASS
```
