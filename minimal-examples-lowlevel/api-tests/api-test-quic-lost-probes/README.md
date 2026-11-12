# lws api test quic lost probes

Replays what stalled a server in the QUIC interop runner's
handshakecorruption case.  Its lost PTO probes were taken for persistent
congestion (RFC 9002 7.6), though one sent between them had got through, so
its congestion window was cut to the minimum.  Then a lost PMTUD probe held
most of that window until an ack came, so its response went only a packet a
PTO, until it gave up on the connection.

An h3 server and its clients run in this process, built with
`LWS_WITH_SYS_FAULT_INJECTION`, with a udp "NAT" between them that sees only
each datagram's direction and size, and keeps a mapping of its own for each
connection, since the first stays up during the second.  For each of two
connections, the NAT
drops the server's last PMTUD probe twice, the second time with nothing else
of the server's in flight, and drops everything the client sends after that.
The server's PTOs then send PINGs alone, P1 to P4, at 1, 3, 7 and 15 times its
PTO, and the NAT passes P4 and the client's ack of it.

 - **no congestion**: the NAT drops P1 and P3 and passes P2.  The client's
   ack of P4 must report P2 too, as an ACK reports every range of PNs it has
   (RFC 9000 13.2.3), and since P2 was acked between the lost P1 and P3, the
   server must find no persistent congestion (RFC 9002 7.6.2).

 - **congestion**: the NAT drops P1, P2 and P3, which is persistent
   congestion, and the server cuts its window to the minimum.  The probe goes
   a third time at once, and the NAT drops it again.  Then the server answers
   a request it held, two packets of the path's size.  A PMTUD probe's bytes
   are not in flight for congestion control (RFC 8899 3), so the answer goes
   at once, not in a PTO's probe.

`wsi/quic_stats` has the server log, as each connection goes, the times it
found persistent congestion, and the packets that took stream data first as a
PTO's probe, past a full congestion window: one connection must have found
persistent congestion, the other not, and neither may have sent stream
data first in a PTO's probe.

```
$ ./lws-api-test-quic-lost-probes -p 7681 \
	--cert ../api-test-ws-close/localhost-100y.cert \
	--key ../api-test-ws-close/localhost-100y.key
```
