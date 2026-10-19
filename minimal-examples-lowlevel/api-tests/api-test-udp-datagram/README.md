# lws-api-test-udp-datagram

Each `lws_write()` on a UDP wsi must go out as exactly one datagram, however
big, as long as the socket can send it.  lws used to cut every write to the
protocol's `tx_packet_size`, or `rx_buffer_size`, plus `LWS_PRE + 4` bytes and
send the rest later, as it does for stream connections.  On UDP that sent the
pieces as separate datagrams the peer cannot join: eg, an auth-dns answer over
1060 bytes reached the client as several datagrams, the first claiming the
full record counts.

A UDP wsi bound on loopback receives from a second, client UDP wsi.  The
sender's protocol has an `rx_buffer_size` of 1024, as auth-dns does; the
receiver's is 0, so it can read a datagram up to the `pt_serv_buf_size` (a
datagram bigger than the receiving protocol's `rx_buffer_size` is truncated to
it, see `READMEs/README.udp.md`).  The sender
writes a 3000-byte datagram, then a 1500-byte one; the receiver must see
exactly those two datagrams, each whole and with its contents intact, in that
order, and nothing after them.

## Commandline

| option | meaning |
|--------|---------|
| `-p PORT` | loopback UDP port the receiver binds (from `lws_get_free_port()`) |

## Run

```
$ ctest -R api-test-udp-datagram
```
