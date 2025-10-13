# lws minimal secure streams server

The application sets up the simplest possible tls + https server on https://localhost:7681

It does it using Secure Streams... information about how the server should
operate is managed by example-policy.json from the example dir.

## build

```
 $ cmake . && make
```

## usage

Commandline option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d15

```
[2024/12/18 07:22:29:2105] U: LWS Secure Streams Server
[2024/12/18 07:22:29:2105] N: lws_create_context: LWS: 4.3.99-v4.3.0-423-gd568eccd, NET CLI SRV H1 H2 WS SS-JSON-POL ConMon IPV6-on
[2024/12/18 07:22:29:2106] N: __lws_lc_tag:  ++ [wsi|0|pipe] (1)
[2024/12/18 07:22:29:2108] N: __lws_lc_tag:  ++ [vh|0|netlink] (1)
[2024/12/18 07:22:29:2115] N: lws_ss_policy_parser_cb: server 'self_localhost' keep 76 0x2c39e250
[2024/12/18 07:22:29:2115] N: lws_ss_policy_parser_cb: server 'self_localhost_key' keep 77 0x2c39e288
[2024/12/18 07:22:29:2116] N: __lws_lc_tag:  ++ [vh|1|_ss_default||-1] (2)
[2024/12/18 07:22:29:3183] N: __lws_lc_tag:  ++ [wsiSScli|0|myserver] (1)
[2024/12/18 07:22:29:3183] N: __lws_lc_tag:  ++ [vh|2|myserver||7681] (3)
[2024/12/18 07:22:29:3183] N:  Vhost 'myserver' using TLS mode
[2024/12/18 07:22:29:3189] N:  SSL ECDH curve 'prime256v1'
[2024/12/18 07:22:29:3190] N: [vh|2|myserver||7681]: lws_socket_bind: source ads 0.0.0.0
[2024/12/18 07:22:29:3191] N: __lws_lc_tag:  ++ [wsi|1|listen|myserver||7681] (2)
[2024/12/18 07:22:29:3192] N: [vh|2|myserver||7681]: lws_socket_bind: source ads ::
[2024/12/18 07:22:29:3192] N: __lws_lc_tag:  ++ [wsi|2|listen|myserver||7681] (3)
[2024/12/18 07:22:29:3192] N: [vh|2|myserver||7681]: lws_tls_check_cert_lifetime:    vhost myserver: cert expiry: 727994d
[2024/12/18 07:22:29:3192] N: [wsiSScli|0|myserver]: lws_ss_check_next_state_ss: (unset) -> LWSSSCS_CREATING
[2024/12/18 07:22:29:3192] N: lws_ss_create: created server myserver
[2024/12/18 07:22:34:3232] N: [vh|2|myserver||7681]: lws_tls_check_cert_lifetime:    vhost myserver: cert expiry: 727994d
[2024/12/18 07:22:35:6162] N: __lws_lc_tag:  ++ [wsisrv|0|myserver|(null)] (1)
[2024/12/18 07:22:35:6163] N: __lws_lc_tag:  ++ [wsiSScli|1|myserver] (2)
[2024/12/18 07:22:35:6164] N: [wsiSScli|1|myserver]: lws_ss_check_next_state_ss: (unset) -> LWSSSCS_CREATING
[2024/12/18 07:22:35:6164] N: [wsiSScli|1|myserver]: lws_ss_check_next_state_ss: LWSSSCS_CREATING -> LWSSSCS_CONNECTING
[2024/12/18 07:22:35:6330] N: __lws_lc_tag:  ++ [mux|0|myserver|h2_sid3_(wsisrv|0|myserver)] (1)
[2024/12/18 07:22:35:6330] N: __lws_lc_tag:  ++ [wsiSScli|2|myserver] (3)
[2024/12/18 07:22:35:6330] N: [wsiSScli|2|myserver]: lws_ss_check_next_state_ss: (unset) -> LWSSSCS_CREATING
[2024/12/18 07:22:35:6331] N: [wsiSScli|2|myserver]: lws_ss_check_next_state_ss: LWSSSCS_CREATING -> LWSSSCS_CONNECTING
[2024/12/18 07:22:35:6332] N: [wsiSScli|2|myserver]: lws_ss_check_next_state_ss: LWSSSCS_CONNECTING -> LWSSSCS_CONNECTED
[2024/12/18 07:22:35:6332] N: [wsiSScli|2|myserver]: lws_ss_check_next_state_ss: LWSSSCS_CONNECTED -> LWSSSCS_SERVER_TXN
[2024/12/18 07:22:35:6332] U: [wsiSScli|2|myserver]: myss_srv_tx: TX 26, flags 0x3, r 0
[2024/12/18 07:22:35:6332] N: [wsiSScli|2|myserver]: lws_ss_check_next_state_ss: LWSSSCS_SERVER_TXN -> LWSSSCS_DISCONNECTED
[2024/12/18 07:22:35:6332] N: [wsiSScli|2|myserver]: lws_ss_check_next_state_ss: LWSSSCS_DISCONNECTED -> LWSSSCS_DESTROYING
[2024/12/18 07:22:35:6332] N: __lws_lc_untag:  -- [wsiSScli|2|myserver] (2) 200μs
[2024/12/18 07:22:35:6332] N: __lws_lc_untag:  -- [mux|0|myserver|h2_sid3_(wsisrv|0|myserver)] (0) 229μs
^C[2024/12/18 07:22:39:8479] N: __lws_lc_untag:  -- [wsi|0|pipe] (2) 10.637s
[2024/12/18 07:22:39:8481] N: __lws_lc_untag:  -- [wsisrv|0|myserver|(null)] (0) 4.231s
[2024/12/18 07:22:39:8481] N: __lws_lc_untag:  -- [wsi|2|listen|myserver||7681] (1) 10.528s
[2024/12/18 07:22:39:8482] N: __lws_lc_untag:  -- [vh|2|myserver||7681] (2) 10.529s
[2024/12/18 07:22:39:8482] N: __lws_lc_untag:  -- [wsi|1|listen|myserver||7681] (0) 10.529s
[2024/12/18 07:22:39:8482] N: __lws_lc_untag:  -- [vh|0|netlink] (1) 10.637s
[2024/12/18 07:22:39:8482] N: [wsiSScli|1|myserver]: lws_ss_check_next_state_ss: LWSSSCS_CONNECTING -> LWSSSCS_DESTROYING
[2024/12/18 07:22:39:8482] N: __lws_lc_untag:  -- [wsiSScli|1|myserver] (1) 4.231s
[2024/12/18 07:22:39:8482] N: [wsiSScli|0|myserver]: lws_ss_check_next_state_ss: LWSSSCS_CREATING -> LWSSSCS_DESTROYING
[2024/12/18 07:22:39:8482] N: __lws_lc_untag:  -- [wsiSScli|0|myserver] (0) 10.529s
[2024/12/18 07:22:39:8486] N: __lws_lc_untag:  -- [vh|1|_ss_default||-1] (0) 10.637s
[2024/12/18 07:22:39:8486] U: Completed: OK (seen expected 0)
```
