# lws-api-test-dht-msg-parse

Coverage for `lws_dht_msg_parse()`, the DHT RPC wire message parser.

In particular it covers the F-051 security fix: the second token of the
message is a hash that consumers like the dnssec and object-store plugins
compose into filesystem paths, so the parser only accepts it when it is
2 - 128 lowercase hex characters — the only shape the protocol itself
generates.  Traversal payloads like `../../etc/shadow`, absolute paths,
uppercase or non-hex characters, and over/undersized tokens are rejected
at the parser, so every consumer inherits the gate.

It also covers `lws_dht_valid_domain_name()` (F-052): the domain string
carried on DHT NOTIFY datagrams is stored in subscription state and later
composed into filesystem paths (zone cache paths, `lws_dir()` walks), so
it must be a presentation-format DNS name — `[A-Za-z0-9._-]` labels of
1 - 63 chars, total length 1 - 253, optional single trailing root dot.
Traversal payloads like `../../x`, path separators, empty labels and junk
bytes are refused, so both the NOTIFY intake gate and the
`do_subscribe_zone()` defense-in-depth check in the dnssec plugin can
rely on it.

## Build

Requires `-DLWS_WITH_DHT=1`.

Run with `ctest -R api-test-dht-msg-parse` from a build directory that
includes the minimal examples.
