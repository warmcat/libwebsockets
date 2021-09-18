# lws minimal ssproxy UART transport

Operates as a secure streams proxy, with a custom transport
for a UART

See ./minimal-examples/embedded/pico/pico-sspc-binance for an RPi pico
based device that wants to use the proxy over UART.

## build

```
 $ cmake . && make
```

## usage

Commandline option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d15
-f| Force connecting to the wrong endpoint to check backoff retry flow
-p <port>|If not given, proxy listens on a Unix Domain Socket, if given listen on specified tcp port
-i <iface>|Optionally specify the UDS path (no -p) or network interface to bind to (if -p also given)

```
[2021/10/04 11:05:55:8347] U: LWS secure streams Proxy [-d<verb>]
[2021/10/04 11:05:55:8348] N: LWS: 4.2.99-v4.2.0-215-g0e30e05c8a, NET CLI SRV H1 H2 WS MQTT SS-JSON-POL SSPROX MbedTLS ConMon IPv6-absent
[2021/10/04 11:05:55:8350] N:  ++ [1316112|wsi|0|pipe] (1)
[2021/10/04 11:05:55:8350] N:  ++ [1316112|vh|0|netlink] (1)
[2021/10/04 11:05:55:8351] N:  ++ [1316112|vh|1|default||-1] (2)
[2021/10/04 11:05:55:8354] N:  ++ [1316112|vh|2|le_via_isrg||-1] (3)
[2021/10/04 11:05:55:8355] N:  ++ [1316112|vh|3|_ss_default||-1] (4)
[2021/10/04 11:05:55:8355] U: cb_proxy_serial_transport: PROTOCOL_INIT default
[2021/10/04 11:05:55:8356] N:  ++ [1316112|wsiSScli|0|captive_portal_detect] (1)
[2021/10/04 11:05:55:8356] N: [1316112|wsiSScli|0|captive_portal_detect]: lws_ss_check_next_state_ss: (unset) -> LWSSSCS_CREATING
[2021/10/04 11:05:55:8356] N: [1316112|wsiSScli|0|captive_portal_detect]: lws_ss_check_next_state_ss: LWSSSCS_CREATING -> LWSSSCS_POLL
[2021/10/04 11:05:55:8356] N: [1316112|wsiSScli|0|captive_portal_detect]: lws_ss_check_next_state_ss: LWSSSCS_POLL -> LWSSSCS_CONNECTING
[2021/10/04 11:05:55:8356] N:  ++ [1316112|wsicli|0|GET/h1/connectivitycheck.android.com/([1316112|wsiSScli|0|captive_portal_det] (1)
[2021/10/04 11:05:55:8452] N: lws_ss_sys_cpd: CPD already ongoing
[2021/10/04 11:05:55:9454] N:  ++ [1316112|wsiSScli|1|fetch_policy] (2)
[2021/10/04 11:05:55:9454] N: [1316112|wsiSScli|1|fetch_policy]: lws_ss_check_next_state_ss: (unset) -> LWSSSCS_CREATING
[2021/10/04 11:05:55:9455] N: [1316112|wsiSScli|1|fetch_policy]: lws_ss_check_next_state_ss: LWSSSCS_CREATING -> LWSSSCS_POLL
[2021/10/04 11:05:55:9455] N: [1316112|wsiSScli|1|fetch_policy]: lws_ss_check_next_state_ss: LWSSSCS_POLL -> LWSSSCS_CONNECTING
[2021/10/04 11:05:55:9455] N:  ++ [1316112|wsicli|1|GET/h1/warmcat.com/([1316112|wsiSScli|1|fetch_policy])] (2)
[2021/10/04 11:05:56:0537] N: [1316112|wsiSScli|0|captive_portal_detect]: lws_ss_check_next_state_ss: LWSSSCS_CONNECTING -> LWSSSCS_CONNECTED
[2021/10/04 11:05:56:0538] N: [1316112|wsiSScli|0|captive_portal_detect]: lws_ss_check_next_state_ss: LWSSSCS_CONNECTED -> LWSSSCS_QOS_ACK_REMOTE
[2021/10/04 11:05:56:0538] N: lws_system_cpd_set: setting CPD result OK
[2021/10/04 11:05:56:0538] N: [1316112|wsiSScli|0|captive_portal_detect]: lws_ss_check_next_state_ss: LWSSSCS_QOS_ACK_REMOTE -> LWSSSCS_DISCONNECTED
[2021/10/04 11:05:56:0538] N: [1316112|wsiSScli|0|captive_portal_detect]: lws_ss_check_next_state_ss: LWSSSCS_DISCONNECTED -> LWSSSCS_DESTROYING
[2021/10/04 11:05:56:0538] N:  -- [1316112|wsiSScli|0|captive_portal_detect] (1) 218.222ms
[2021/10/04 11:05:56:0539] N:  -- [1316112|wsicli|0|GET/h1/connectivitycheck.android.com/([1316112|wsiSScli|0|captive_portal_det] (1) 218.250ms
[2021/10/04 11:05:56:1210] N: [1316112|wsiSScli|1|fetch_policy]: lws_ss_check_next_state_ss: LWSSSCS_CONNECTING -> LWSSSCS_CONNECTED
[2021/10/04 11:05:56:1546] N: [1316112|wsiSScli|1|fetch_policy]: lws_ss_check_next_state_ss: LWSSSCS_CONNECTED -> LWSSSCS_QOS_ACK_REMOTE
[2021/10/04 11:05:56:1546] W: lws_ss_destroy: conn->ss->wsi 0 0
[2021/10/04 11:05:56:1547] N:  -- [1316112|wsicli|1|GET/h1/warmcat.com/([1316112|wsiSScli|1|fetch_policy])] (0) 209.245ms
[2021/10/04 11:05:56:1548] N: [1316112|wsiSScli|1|fetch_policy]: lws_ss_check_next_state_ss: LWSSSCS_QOS_ACK_REMOTE -> LWSSSCS_DISCONNECTED
[2021/10/04 11:05:56:1548] N: [1316112|wsiSScli|1|fetch_policy]: lws_ss_check_next_state_ss: LWSSSCS_DISCONNECTED -> LWSSSCS_DESTROYING
[2021/10/04 11:05:56:1548] N:  -- [1316112|wsiSScli|1|fetch_policy] (0) 209.356ms
[2021/10/04 11:05:56:1548] N:  -- [1316112|vh|2|le_via_isrg||-1] (3) 319.414ms
[2021/10/04 11:05:56:1548] N:  ++ [1316112|vh|4|s3-root-cert||-1] (4)
[2021/10/04 11:05:56:1548] N:  ++ [1316112|vh|5|digicert||-1] (5)
[2021/10/04 11:05:56:1549] N:  ++ [1316112|vh|6|le_via_isrg||-1] (6)
[2021/10/04 11:05:56:1549] N:  ++ [1316112|vh|7|arca1||-1] (7)
[2021/10/04 11:05:56:1549] N:  ++ [1316112|vh|8|mqtt_amz_iot||-1] (8)
[2021/10/04 11:05:56:1549] N:  ++ [1316112|vh|9|avs_via_starfield||-1] (9)
[2021/10/04 11:05:56:1550] N:  ++ [1316112|vh|a|api_amazon_com||-1] (10)
[2021/10/04 11:05:56:1550] U: lws_transport_mux_init_proxy_server: priv_inward (nil)
[2021/10/04 11:05:56:2099] N: open_serial_port: serial port opened 6
[2021/10/04 11:05:56:2099] U: txp_serial_init_proxy_server: txp_priv_inward 0x1c70080
[2021/10/04 11:05:56:2099] N:  ++ [1316112|wsisrv|0|adopted] (1)
[2021/10/04 11:05:56:2099] N: LWS_CALLBACK_RAW_ADOPT_FILE
[2021/10/04 11:05:56:2099] U: txp_serial_init_proxy_server: OK (txp_priv_in 0x1c70080)
[2021/10/04 11:05:56:2099] U: lws_transport_mux_init_proxy_server: OK
[2021/10/04 11:05:56:2099] N: sul_ping_cb: issuing ping
[2021/10/04 11:05:56:2241] N: 
[2021/10/04 11:05:56:2242] N: 0000: F9 F6 00 00 00 00 1F 2F 89 9C F7 00 00 01 27 29    ......./......')
[2021/10/04 11:05:56:2242] N: 0010: 4E A2 7B 00 00 00 00 1F 2F 8A 71                   N.{...../.q     
[2021/10/04 11:05:56:2242] N: 
[2021/10/04 11:05:56:2242] U: lws_transport_mux_rx_parse: got PING
[2021/10/04 11:05:56:2242] U: lws_transport_mux_rx_parse: got PONG
[2021/10/04 11:05:56:2242] U: lws_transport_set_link: ******* transport mux link is UP
[2021/10/04 11:05:56:2400] N: 
[2021/10/04 11:05:56:2400] N: 0000: F8 00 00 00 00 1F 2F C1 12                         ....../..       
[2021/10/04 11:05:56:2400] N: 
[2021/10/04 11:05:56:2400] U: lws_transport_mux_rx_parse: got PONGACK: ustime 523223314
[2021/10/04 11:05:56:7500] N: 
[2021/10/04 11:05:56:7500] N: 0000: F0 FF F0 FE                                        ....            
[2021/10/04 11:05:56:7501] N: 
[2021/10/04 11:05:56:7501] N: ltm_ch_opens
[2021/10/04 11:05:56:7501] N: ltm_ch_opens
[2021/10/04 11:05:56:7659] N: 
[2021/10/04 11:05:56:7659] N: 0000: F5 FF 00 13 AA 00 10 01 FF FF FF FF 1D 64 29 1F    .............d).
[2021/10/04 11:05:56:7659] N: 0010: 62 69 6E 61 6E 63 65 F5 FE 00 17 AA 00 14 01 FF    binance.........
[2021/10/04 11:05:56:7659] N: 0020: FF FF FF 1D C8 CA BB 6D 69 6E 74 65 73 74 2D 6C    .......mintest-l
[2021/10/04 11:05:56:7659] N: 0030: 77 73                                              ws              
[2021/10/04 11:05:56:7659] N: 
[2021/10/04 11:05:56:7659] N: ltm_ch_payload
[2021/10/04 11:05:56:7659] N: lws_transport_path_proxy_dump: ltm_ch_payload: MUX: 0x1c70080, IN: ops txp_inside_proxy, priv (nil), ONW: ops txp_inside_proxy, priv (nil)
[2021/10/04 11:05:56:7659] N:  ++ [1316112|wsiSScli|2|binance|v1|4294967295] (1)
[2021/10/04 11:05:56:7659] N: [1316112|wsiSScli|2|binance|v1|4294967295]: lws_ss_check_next_state_ss: (unset) -> LWSSSCS_CREATING
[2021/10/04 11:05:56:7659] N: lws_sss_proxy_onward_state: [1316112|wsiSScli|2|binance|v1|4294967295]: initializing dsh max len 262144
[2021/10/04 11:05:56:7659] N: [1316112|wsiSScli|2|binance|v1|4294967295]: lws_ss_check_next_state_ss: LWSSSCS_CREATING -> LWSSSCS_CONNECTING
[2021/10/04 11:05:56:7659] N:  ++ [1316112|wsicli|2|WS/h1/fstream.binance.com/([1316112|wsiSScli|2|binance|v1|4294967295])] (1)
[2021/10/04 11:05:56:7675] N: ltm_ch_payload
[2021/10/04 11:05:56:7675] N: lws_transport_path_proxy_dump: ltm_ch_payload: MUX: 0x1c70080, IN: ops txp_inside_proxy, priv (nil), ONW: ops txp_inside_proxy, priv (nil)
[2021/10/04 11:05:56:7675] N:  ++ [1316112|wsiSScli|3|mintest-lws|v1|4294967295] (2)
[2021/10/04 11:05:56:7675] N: [1316112|wsiSScli|3|mintest-lws|v1|4294967295]: lws_ss_check_next_state_ss: (unset) -> LWSSSCS_CREATING
[2021/10/04 11:05:56:7675] N: lws_sss_proxy_onward_state: [1316112|wsiSScli|3|mintest-lws|v1|4294967295]: initializing dsh max len 32768
[2021/10/04 11:05:56:7818] N: 
[2021/10/04 11:05:56:7818] N: 0000: F5 FF 00 03 AB 00 00                               .......         
[2021/10/04 11:05:56:7818] N: 
[2021/10/04 11:05:56:7818] N: ltm_ch_payload
[2021/10/04 11:05:56:7818] N: lws_transport_path_proxy_dump: ltm_ch_payload: MUX: 0x1c70080, IN: ops txp_inside_proxy, priv (nil), ONW: ops txp_inside_proxy, priv (nil)
[2021/10/04 11:05:56:7818] N: lws_ss_proxy_deserialize_parse: ONWARD_CONNECT
[2021/10/04 11:05:57:8864] N: [1316112|wsiSScli|2|binance|v1|4294967295]: lws_ss_check_next_state_ss: LWSSSCS_CONNECTING -> LWSSSCS_CONNECTED
[2021/10/04 11:05:57:8980] N: 
[2021/10/04 11:05:57:8981] N: 0000: F5 FE 00 03 AB 00 00                               .......         
[2021/10/04 11:05:57:8981] N: 
[2021/10/04 11:05:57:8981] N: ltm_ch_payload
[2021/10/04 11:05:57:8981] N: lws_transport_path_proxy_dump: ltm_ch_payload: MUX: 0x1c70080, IN: ops txp_inside_proxy, priv (nil), ONW: ops txp_inside_proxy, priv (nil)
[2021/10/04 11:05:57:8981] N: lws_ss_proxy_deserialize_parse: ONWARD_CONNECT
[2021/10/04 11:05:57:8981] N: [1316112|wsiSScli|3|mintest-lws|v1|4294967295]: lws_ss_check_next_state_ss: LWSSSCS_CREATING -> LWSSSCS_CONNECTING
[2021/10/04 11:05:57:8981] N:  ++ [1316112|wsiSSPonw|0|GET/h1/libwebsockets.org/([1316112|wsiSScli|3|mintest-lws|v1|4294967295])] (1)
[2021/10/04 11:05:57:9173] N: lws_ss_serialize_rx_payload: dsh c2p 0, p2c 696
[2021/10/04 11:05:57:9309] N: lws_ss_serialize_rx_payload: dsh c2p 0, p2c 896
[2021/10/04 11:05:57:9513] N: lws_ss_serialize_rx_payload: dsh c2p 0, p2c 512
[2021/10/04 11:05:57:9663] N: lws_ss_serialize_rx_payload: dsh c2p 0, p2c 264
[2021/10/04 11:05:57:9860] N: lws_ss_serialize_rx_payload: dsh c2p 0, p2c 472
[2021/10/04 11:05:58:0126] N: [1316112|wsiSScli|3|mintest-lws|v1|4294967295]: lws_ss_check_next_state_ss: LWSSSCS_CONNECTING -> LWSSSCS_CONNECTED
[2021/10/04 11:05:58:0136] N: lws_ss_serialize_rx_payload: dsh c2p 0, p2c 1744
[2021/10/04 11:05:58:0136] N: lws_ss_serialize_rx_payload: dsh c2p 0, p2c 3344
[2021/10/04 11:05:58:0136] N: lws_ss_serialize_rx_payload: dsh c2p 0, p2c 3720
[2021/10/04 11:05:58:0136] N: lws_ss_serialize_rx_payload: dsh c2p 0, p2c 5392
[2021/10/04 11:05:58:0136] N: lws_ss_serialize_rx_payload: dsh c2p 0, p2c 6752
[2021/10/04 11:05:58:0136] N: lws_ss_serialize_rx_payload: dsh c2p 0, p2c 6840
[2021/10/04 11:05:58:0137] N: [1316112|wsiSScli|3|mintest-lws|v1|4294967295]: lws_ss_check_next_state_ss: LWSSSCS_CONNECTED -> LWSSSCS_QOS_ACK_REMOTE
[2021/10/04 11:05:58:0137] N: [1316112|wsiSScli|3|mintest-lws|v1|4294967295]: lws_ss_check_next_state_ss: LWSSSCS_QOS_ACK_REMOTE -> LWSSSCS_DISCONNECTED
[2021/10/04 11:05:58:0138] N:  -- [1316112|wsiSSPonw|0|GET/h1/libwebsockets.org/([1316112|wsiSScli|3|mintest-lws|v1|4294967295])] (0) 115.696ms
[2021/10/04 11:05:58:0197] N: lws_ss_serialize_rx_payload: dsh c2p 0, p2c 464
[2021/10/04 11:05:58:0555] N: lws_ss_serialize_rx_payload: dsh c2p 0, p2c 464
[2021/10/04 11:05:58:0936] N: lws_ss_serialize_rx_payload: dsh c2p 0, p2c 848
[2021/10/04 11:05:58:1322] N: lws_ss_serialize_rx_payload: dsh c2p 0, p2c 552
[2021/10/04 11:05:58:1647] N: lws_ss_serialize_rx_payload: dsh c2p 0, p2c 1016
[2021/10/04 11:05:58:2000] N: lws_ss_serialize_rx_payload: dsh c2p 0, p2c 448
[2021/10/04 11:05:58:2313] N: lws_ss_serialize_rx_payload: dsh c2p 0, p2c 888
[2021/10/04 11:05:58:2514] N: lws_ss_serialize_rx_payload: dsh c2p 0, p2c 264
[2021/10/04 11:05:58:2562] N: lws_ss_serialize_rx_payload: dsh c2p 0, p2c 464
[2021/10/04 11:05:58:2639] N: lws_ss_serialize_rx_payload: dsh c2p 0, p2c 952
[2021/10/04 11:05:58:2972] N: lws_ss_serialize_rx_payload: dsh c2p 0, p2c 2072
[2021/10/04 11:05:58:3304] N: lws_ss_serialize_rx_payload: dsh c2p 0, p2c 1776
[2021/10/04 11:05:58:3321] N: lws_ss_serialize_rx_payload: dsh c2p 0, p2c 1976
[2021/10/04 11:05:58:3364] N: lws_ss_serialize_rx_payload: dsh c2p 0, p2c 1048
[2021/10/04 11:05:58:3464] N: lws_ss_serialize_rx_payload: dsh c2p 0, p2c 1248
[2021/10/04 11:05:58:3515] N: lws_ss_serialize_rx_payload: dsh c2p 0, p2c 264
[2021/10/04 11:05:58:3629] N: lws_ss_serialize_rx_payload: dsh c2p 0, p2c 1088
[2021/10/04 11:05:58:3706] N: lws_ss_serialize_rx_payload: dsh c2p 0, p2c 272
[2021/10/04 11:05:58:3714] N: lws_ss_serialize_rx_payload: dsh c2p 0, p2c 264
...
```
