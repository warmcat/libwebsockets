## Using UDP in lws

UDP is supported in lws... the quickest way is to use the api
`lws_create_adopt_udp()` which returns a wsi bound to the provided
vhost, protocol, `lws_retry` struct, dns address and port.

The wsi can be treated normally and `lws_write()` used to write on
it.

## Datagram size

Each `lws_write()` on a UDP wsi sends exactly one datagram, of all the bytes
given.  Unlike a stream connection, the write is not cut to the protocol's
`tx_packet_size` or `rx_buffer_size` with the rest sent later, since the pieces
would arrive as separate datagrams the peer could not join.  The datagram goes
whole, or the write fails, eg with `EMSGSIZE` when it is bigger than the socket
can send: the UDP payload limit is 65507 bytes on IPv4 and 65527 on IPv6, and
it is up to the network stack how a datagram bigger than the path MTU is
fragmented.  If the socket can't take it right now, lws keeps the whole
datagram and sends it as one when the socket is writable again.

It's up to the application protocol to keep datagrams to a size its peers
accept, eg, DNS over UDP to the EDNS payload size the client advertised.

On receive, each `LWS_CALLBACK_RAW_RX` is one datagram, read into at most the
protocol's `rx_buffer_size`, or if that is 0 or bigger, the context's
`pt_serv_buf_size` less `LWS_PRE` (4096 - `LWS_PRE` by default, 2048 -
`LWS_PRE` on FreeRTOS).  A datagram bigger than that is truncated to it, so
set `rx_buffer_size` for the largest datagram the protocol accepts.

## Implementing UDP retries

Retries are important in udp but there's no standardized ack method
unlike tcp.  Lws allows you to bind an `lws_retry` struct describing
the policy to the udp wsi, but since one UDP socket may have many
transactions in flight, the `lws_sul` and `uint16_t` to count the
retries must live in the user's transaction object like this

```
...
	lws_sorted_usec_list_t	sul;
	uint16_t		retry;
...
```

in the `LWS_CALLBACK_RAW_WRITEABLE` callback, before doing the write,
set up the retry like this

```
	if (lws_dll2_is_detached(&transaction->sul_write.list) &&
	    lws_retry_sul_schedule_retry_wsi(wsi, &transaction->sul_write,
					     transaction_retry_write_cb,
					     &transaction->retry_count_write)) {
			/* we have reached the end of our concealed retries */
		lwsl_warn("%s: concealed retries done, failing\n", __func__);
		goto retry_conn;
	}
```

This manages the retry counter in the transaction object, guards against it wrapping,
selects the timeout using the policy bound to the wsi, and sets the `lws_sul` in the
transaction object to call the given callback if the sul time expires.

In the callback, it should simply call `lws_callback_on_writable()` for the udp wsi.

## Simulating packetloss

You can simulate udp packetloss at tx and rx by using the Fault Injection apis
with the well-known fault names "udp_tx_loss" and "udp_rx_loss", typically
with the probabilistic setting, in commandline format something like
`--fault-injection "wsi/udp_tx_loss(10%)"`
