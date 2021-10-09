# lws minimal secure streams sink hello_world

This example shows how to register your own SS as a "sink", that is a "server"
that handles a given streamtype locally.

User code just creates its own SS of that streamtype as usual, if it is marked
in the policy as a local_sink

```
	"local_sink": true,
```

and the sink was registered, then the SS is fulfilled by the sink rather than
directly making onward connections.  This lets you, eg handle streams completely
locally, or intercept or store-and-forward their content to the cloud using
another SS when convenient.

Like any server, when you connect to it, at the server-side it creates an
"accepted" sink SS specific to the connection, which is closed when the incoming
connection closes.

The example shows how to register the sink, and create a normal SS of the same
streamtype name.  The source then sends a "hello_world" message to the sink
instance, and the sink instance responds with a message back to the source.

In this example, the source getting the ack message makes us exit with a
success return.

Sinks can be registered where the policy is in your system, either directly if
there is no proxying, or at the proxy process when there is.

## build

```
 $ cmake . && make
```

## usage

Commandline option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d15

```
[2021/10/11 06:25:54:8413] U: LWS Secure Streams Sink hello_world
[2021/10/11 06:25:54:8757] N: LWS: 4.3.99-v4.3.0-19-g9da508e91b, NET CLI SRV H1 H2 WS MQTT SS-JSON-POL SSPROX ConMon IPv6-absent
[2021/10/11 06:25:54:8876] N:  ++ [1819937|wsi|0|pipe] (1)
[2021/10/11 06:25:54:8920] N:  ++ [1819937|vh|0|netlink] (1)
[2021/10/11 06:25:55:0233] N:  ++ [1819937|vh|1|_ss_default||-1] (2)
[2021/10/11 06:25:55:4867] N: lws_ss_create: registered sink sink_hello_world
[2021/10/11 06:25:55:4881] N:  ++ [1819937|SSsrc|0|sink_hello_world] (1)
[2021/10/11 06:25:55:4890] N:  ++ [1819937|SSsink|0|sink_hello_world] (1)
[2021/10/11 06:25:55:4907] N: [1819937|SSsink|0|sink_hello_world]: lws_ss_check_next_state_ss: (unset) -> LWSSSCS_CREATING
[2021/10/11 06:25:55:4929] N: [1819937|SSsink|0|sink_hello_world]: lws_ss_check_next_state_ss: LWSSSCS_CREATING -> LWSSSCS_CONNECTING
[2021/10/11 06:25:55:4930] N: [1819937|SSsink|0|sink_hello_world]: lws_ss_check_next_state_ss: LWSSSCS_CONNECTING -> LWSSSCS_CONNECTED
[2021/10/11 06:25:55:4935] N: [1819937|SSsrc|0|sink_hello_world]: lws_ss_create: bound to sink
[2021/10/11 06:25:55:4940] N: [1819937|SSsrc|0|sink_hello_world]: lws_ss_check_next_state_ss: (unset) -> LWSSSCS_CREATING
[2021/10/11 06:25:55:4942] N: myss_src_state: CREATING
[2021/10/11 06:25:55:4945] N: [1819937|SSsrc|0|sink_hello_world]: lws_ss_check_next_state_ss: LWSSSCS_CREATING -> LWSSSCS_CONNECTING
[2021/10/11 06:25:55:4946] N: [1819937|SSsrc|0|sink_hello_world]: lws_ss_check_next_state_ss: LWSSSCS_CONNECTING -> LWSSSCS_CONNECTED
[2021/10/11 06:25:55:4950] N: [1819937|SSsink|0|sink_hello_world]: _lws_ss_request_tx: Req tx
[2021/10/11 06:25:55:4962] U: [1819937|SSsrc|0|sink_hello_world]: myss_src_tx: TX 39, flags 0x3, r 0
[2021/10/11 06:25:55:4969] N: [1819937|SSsink|0|sink_hello_world]: myss_sink_rx: len 39, flags 0x3
[2021/10/11 06:25:55:4974] N:
[2021/10/11 06:25:55:4987] N: 0000: 46 72 6F 6D 20 53 6F 75 72 63 65 3A 20 48 65 6C    From Source: Hel
[2021/10/11 06:25:55:4989] N: 0010: 6C 6F 20 57 6F 72 6C 64 3A 20 31 38 35 35 37 30    lo World: 185570
[2021/10/11 06:25:55:4993] N: 0020: 37 36 35 36 33 31 38                               7656318
[2021/10/11 06:25:55:4995] N:
[2021/10/11 06:25:55:4999] N: [1819937|SSsrc|0|sink_hello_world]: _lws_ss_request_tx: Req tx
[2021/10/11 06:25:55:5009] U: [1819937|SSsink|0|sink_hello_world]: myss_sink_tx: TX 37, flags 0x3, r 0
[2021/10/11 06:25:55:5012] N: [1819937|SSsrc|0|sink_hello_world]: myss_src_rx: len 37, flags 0x3
[2021/10/11 06:25:55:5014] N:
[2021/10/11 06:25:55:5015] N: 0000: 46 72 6F 6D 20 53 69 6E 6B 3A 20 48 65 6C 6C 6F    From Sink: Hello
[2021/10/11 06:25:55:5015] N: 0010: 20 57 6F 72 6C 64 3A 20 31 38 35 35 37 30 37 36     World: 18557076
[2021/10/11 06:25:55:5016] N: 0020: 36 31 33 32 34                                     61324
[2021/10/11 06:25:55:5016] N:
[2021/10/11 06:25:55:5166] N:  -- [1819937|wsi|0|pipe] (0) 628.987ms
[2021/10/11 06:25:55:5177] N:  -- [1819937|vh|0|netlink] (1) 625.669ms
[2021/10/11 06:25:55:5205] N: [1819937|SSsink|0|sink_hello_world]: lws_ss_check_next_state_ss: LWSSSCS_CONNECTED -> LWSSSCS_DISCONNECTED
[2021/10/11 06:25:55:5207] N: [1819937|SSsink|0|sink_hello_world]: lws_ss_check_next_state_ss: LWSSSCS_DISCONNECTED -> LWSSSCS_DESTROYING
[2021/10/11 06:25:55:5211] N:  -- [1819937|SSsink|0|sink_hello_world] (0) 32.090ms
[2021/10/11 06:25:55:5215] N: [1819937|SSsrc|0|sink_hello_world]: lws_ss_check_next_state_ss: LWSSSCS_CONNECTED -> LWSSSCS_DISCONNECTED
[2021/10/11 06:25:55:5215] N: [1819937|SSsrc|0|sink_hello_world]: lws_ss_check_next_state_ss: LWSSSCS_DISCONNECTED -> LWSSSCS_DESTROYING
[2021/10/11 06:25:55:5216] N:  -- [1819937|SSsrc|0|sink_hello_world] (0) 33.434ms
[2021/10/11 06:25:55:5431] N:  -- [1819937|vh|1|_ss_default||-1] (0) 519.819ms
[2021/10/11 06:25:55:5487] U: Completed: OK (seen expected 0)
```