# lws api test h3 qpack blocked

QPACK blocked streams (RFC 9204 2.1.2) on h3.  A request whose field section
refers to a dynamic table insert the server doesn't have yet must wait for it,
not fail, and no more streams may wait at once than the server advertised with
`SETTINGS_QPACK_BLOCKED_STREAMS` (8 for lws).

An h3 server and its client run in this process.  The client's requests refer
to the one cookie entry its encoder stream inserts by fault injection, and the
servers answer 200 only if the cookie they decoded is that entry's.

 - Part 1: the insert only goes after the connection's first request did
   (`h3_qpack_enc_big_entry_late`), so the request arrives first and blocks.
   It must be answered 200 once the insert comes.

 - Part 2: the insert never goes (`h3_qpack_enc_big_entry_never`), and 9
   requests refer to it, which the client sends although the server lets only
   8 wait (`h3_qpack_enc_no_hold`).  The server must fail the connection,
   answering none of them.

 - Part 3: 8 requests refer to the insert that never goes, and the client gives
   up on them.  Then one more does, with a request that refers to nothing.  If
   the server still counted the ones given up on, the one more is too many and
   fails the connection, so the plain request must be answered 200.

 - Part 4: a second server lets no stream wait
   (`h3_qpack_blocked_streams_0`), and the insert again only goes after the
   request tried to.  The client may not send a request the server might have
   to block, so it must hold it until the server acknowledges the insert, and
   then it is answered 200.  Sent at once, it would arrive before the insert
   and the server would fail the connection.

It needs a build with `-DLWS_WITH_SYS_FAULT_INJECTION=1`.

```
$ ./lws-api-test-h3-qpack-blocked -p 7681 --nb-port 7682 \
	--cert ../api-test-ws-close/localhost-100y.cert \
	--key ../api-test-ws-close/localhost-100y.key
```
