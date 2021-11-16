# lws minimal secure streams mqtt

The application connects test.mosquitto.org and exchange MQTT messages.

For TLS connetion, you can generate your own certificate on
https://test.mosquitto.org/ssl/

## build

```
 $ cmake . && make
```

## usage

Commandline option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d15
--test-nontls|Connect test.mosquitto.org without tls

```
[2021/11/08 08:53:07:1372] U: LWS secure streams mqtt test client [-d<verb>]
[2021/11/08 08:53:07:1378] N: lws_create_context: LWS: 4.3.99-v4.3.0-89-g57e60f25, NET CLI SRV H1 H2 WS MQTT SS-JSON-POL SSPROX ConMon IPv6-absent
[2021/11/08 08:53:07:1380] N: __lws_lc_tag:  ++ [98522|wsi|0|pipe] (1)
[2021/11/08 08:53:07:1405] N: __lws_lc_tag:  ++ [98522|vh|0|mosq_org||-1] (1)
[2021/11/08 08:53:07:1546] N: __lws_lc_tag:  ++ [98522|vh|1|_ss_default||-1] (2)
[2021/11/08 08:53:07:1662] N: __lws_lc_tag:  ++ [98522|wsiSScli|0|mosq_tls] (1)
[2021/11/08 08:53:07:1662] N: [98522|wsiSScli|0|mosq_tls]: lws_ss_check_next_state_ss: (unset) -> LWSSSCS_CREATING
[2021/11/08 08:53:07:1662] U: myss_state: LWSSSCS_CREATING, ord 0x0
[2021/11/08 08:53:07:1662] N: [98522|wsiSScli|0|mosq_tls]: lws_ss_check_next_state_ss: LWSSSCS_CREATING -> LWSSSCS_POLL
[2021/11/08 08:53:07:1662] U: myss_state: LWSSSCS_POLL, ord 0x0
[2021/11/08 08:53:07:1662] N: secstream_connect_munge_mqtt - Client ID = SN12345678
[2021/11/08 08:53:07:1662] N: [98522|wsiSScli|0|mosq_tls]: lws_ss_check_next_state_ss: LWSSSCS_POLL -> LWSSSCS_CONNECTING
[2021/11/08 08:53:07:1662] U: myss_state: LWSSSCS_CONNECTING, ord 0x0
[2021/11/08 08:53:07:1663] N: lws_mqtt_generate_id: User space provided a client ID 'SN12345678'
[2021/11/08 08:53:07:1663] N: __lws_lc_tag:  ++ [98522|wsicli|0|MQTT/mqtt/test.mosquitto.org/([98522|wsiSScli|0|mosq_tls])] (1)
[2021/11/08 08:53:07:1716] N: [98522|wsicli|0|MQTT/mqtt/test.mosquitto.org/([98522|wsiSScli|0|mosq_tls])]: lws_client_connect_3_connect: trying 5.196.95.208
[2021/11/08 08:53:07:1718] U: myss_state: LWSSSCS_EVENT_WAIT_CANCELLED, ord 0x0
[2021/11/08 08:53:07:3293] N: lws_ssl_client_bio_create: set system client cert 0
[2021/11/08 08:53:13:9751] N: __lws_lc_tag:  ++ [98522|mux|0|mosq_org|mqtt_sid1] (1)
[2021/11/08 08:53:13:9752] N: _lws_mqtt_rx_parser: migrated nwsi [98522|wsicli|0|MQTT/mqtt/test.mosquitto.org/([98522|wsiSScli|0|mosq_tls])] to sid 1 [98522|mux|0|mosq_org|mqtt_sid1]
[2021/11/08 08:53:13:9753] N: secstream_mqtt: [98522|wsiSScli|0|mosq_tls]: WRITEABLE
[2021/11/08 08:53:13:9753] N: secstream_mqtt_subscribe, expbuf - test/topic1
[2021/11/08 08:53:13:9753] N: secstream_mqtt_subscribe: subscribing test/topic1
[2021/11/08 08:53:14:1969] N: [98522|wsiSScli|0|mosq_tls]: lws_ss_check_next_state_ss: LWSSSCS_CONNECTING -> LWSSSCS_CONNECTED
[2021/11/08 08:53:14:1970] U: myss_state: LWSSSCS_CONNECTED, ord 0x0
[2021/11/08 08:53:14:1970] N: secstream_mqtt: [98522|wsiSScli|0|mosq_tls]: WRITEABLE
[2021/11/08 08:53:14:1970] U: Start of message
[2021/11/08 08:53:14:1970] U: myss_tx: h: 0x7fa25160a880, [0]sending 0 - 23 flags 0x3
[2021/11/08 08:53:14:1970] N: secstream_mqtt_publish, expbuf - test/topic1
[2021/11/08 08:53:14:1970] N: secstream_mqtt_publish: payload len 23
[2021/11/08 08:53:14:1972] N: [98522|wsiSScli|0|mosq_tls]: lws_ss_check_next_state_ss: LWSSSCS_CONNECTED -> LWSSSCS_QOS_ACK_REMOTE
[2021/11/08 08:53:14:1972] U: myss_state: LWSSSCS_QOS_ACK_REMOTE, ord 0x0
[2021/11/08 08:53:18:5310] U: myss_rx: len 23, flags: 3
[2021/11/08 08:53:18:5312] N: __lws_lc_untag:  -- [98522|wsi|0|pipe] (0) 11.393s
[2021/11/08 08:53:18:5312] N: [98522|wsiSScli|0|mosq_tls]: lws_ss_check_next_state_ss: LWSSSCS_QOS_ACK_REMOTE -> LWSSSCS_DISCONNECTED
[2021/11/08 08:53:18:5312] U: myss_state: LWSSSCS_DISCONNECTED, ord 0x0
[2021/11/08 08:53:18:5312] N: __lws_lc_untag:  -- [98522|mux|0|mosq_org|mqtt_sid1] (0) 4.556s
[2021/11/08 08:53:18:5317] N: __lws_lc_untag:  -- [98522|vh|0|mosq_org||-1] (1) 11.391s
[2021/11/08 08:53:18:5318] N: __lws_lc_untag:  -- [98522|wsicli|0|MQTT/mqtt/test.mosquitto.org/([98522|wsiSScli|0|mosq_tls])] (0) 11.365s
[2021/11/08 08:53:18:5318] N: [98522|wsiSScli|0|mosq_tls]: lws_ss_check_next_state_ss: LWSSSCS_DISCONNECTED -> LWSSSCS_DESTROYING
[2021/11/08 08:53:18:5319] U: myss_state: LWSSSCS_DESTROYING, ord 0x0
[2021/11/08 08:53:18:5319] N: __lws_lc_untag:  -- [98522|wsiSScli|0|mosq_tls] (0) 11.365s
[2021/11/08 08:53:18:5355] N: __lws_lc_untag:  -- [98522|vh|1|_ss_default||-1] (0) 11.380s
[2021/11/08 08:53:18:5356] U: Completed: OK (seen expected 0)
```

