# lws api test quic ack work

What a QUIC peer's ACKs cost must be bounded by what they say, not by what
they say times what we have in flight (G-648).  Each ACK range used to cost a
walk of the whole in-flight list, and nothing limited the ACK frames in a
packet.

An h3 server and its client run in this process, built with
`LWS_WITH_SYS_FAULT_INJECTION`.  The client GETs 768KiB, with the faults
`wsi/quic_ack_ranges` (ACKs carry ~100 extra one-PN ranges, three copies a
packet, every other one lagging 16 PNs so frames stay in flight),
`wsi/quic_ack_late` (ACKs every 32 packets) and `wsi/quic_stats` (each
connection logs what the ACKs it got cost it).

The transfer must complete, the server must have ignored the copies, and no
ACK frame may have looked at more in-flight frames than one per range plus
two per frame in flight when it came, plus a few where the walks stop.

Nothing may go with frames in it while congestion control holds them: an ACK
we owe goes on its own then (G-649).

With `--path-challenges`, the client and server instead add 16 PATH_CHALLENGEs
to each packet with frames in it (`wsi/quic_path_challenge_flood`), and
neither may have more than 12 PATH_RESPONSEs waiting or in flight at once
(G-649).

With `--lost-finished`, the client's Handshake packet with its Finished in it
is damaged on the way the first three times (`wsi/quic_corrupt_finished`), so
the server holds the client's 1-RTT packets that came after it until the
client's PTO sends the Finished again.  The server must have held one for at
least 50ms, reported that wait in the ACK Delay of its ACK (RFC 9000 13.2.5),
and the client must have taken all of it, far past the 25ms max_ack_delay,
since its handshake was not confirmed yet (RFC 9002 5.3).  Taking the wait for
path RTT instead backs the client's PTO off by as much, so a request lost then
goes again too late.  The server sends nothing in 1-RTT until its handshake
completes (`wsi/quic_no_half_rtt`), so the largest client packet it holds,
whose hold its ACK Delay reports, is one the client takes an RTT sample from,
not an ACK.

Each end's 1-RTT ACKs also report 10ms more ACK Delay than they held them for
(`wsi/quic_ack_delay_over`), so the client's RTT sample less the server's ACK
Delay is below its min_rtt, as it is by jitter alone half the time when the
server reports its hold exactly.  The client must still have taken at least
half the hold off its RTT sample, flooring it at min_rtt, rather than taking
the whole sample for path RTT.

```
$ ./lws-api-test-quic-ack-work -p 7681 --cert ../api-test-ws-close/localhost-100y.cert \
	--key ../api-test-ws-close/localhost-100y.key
$ ./lws-api-test-quic-ack-work -p 7681 --cert ../api-test-ws-close/localhost-100y.cert \
	--key ../api-test-ws-close/localhost-100y.key --path-challenges
$ ./lws-api-test-quic-ack-work -p 7681 --cert ../api-test-ws-close/localhost-100y.cert \
	--key ../api-test-ws-close/localhost-100y.key --lost-finished
```
