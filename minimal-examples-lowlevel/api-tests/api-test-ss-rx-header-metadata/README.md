# lws api test ss rx header metadata

A Secure Streams policy can capture a response header into metadata, either a
header lws knows (`cache-control:`) or a custom one (`x-cust:`).  The metadata
must hold exactly the header's value:

 - a well-known header the server sent more than once, with another header
   between them, has its values joined with `, `, the way `lws_hdr_copy()`
   gives them, and nothing else that was in the headers
 - a custom header has its value
 - a second response on the same stream replaces both values

With `LWS_WITH_SS_DIRECT_PROTOCOL_STR`, a second stream does the same with a
`direct_proto_str` policy, where the app asks `lws_ss_get_metadata()` for the
headers by name, without the policy naming them.

A raw socket server in the same process answers each request on a stream with
the next of the test's responses.

```
$ ./lws-api-test-ss-rx-header-metadata
```

Option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d15
--server <address>|Address of the test server (default localhost)
--help|Show the options
