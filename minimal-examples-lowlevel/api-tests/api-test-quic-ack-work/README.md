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

```
$ ./lws-api-test-quic-ack-work -p 7681 --cert ../api-test-ws-close/localhost-100y.cert \
	--key ../api-test-ws-close/localhost-100y.key
$ ./lws-api-test-quic-ack-work -p 7681 --cert ../api-test-ws-close/localhost-100y.cert \
	--key ../api-test-ws-close/localhost-100y.key --path-challenges
```
