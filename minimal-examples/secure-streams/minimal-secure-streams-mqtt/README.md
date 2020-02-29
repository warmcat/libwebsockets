# lws minimal secure streams-mqtt

The application connects to AWS IoT using a prepared hardcoded client cert and
key, subscribes to the topic "test/topic0" and publishes a little JSON fragment
every few seconds with the unixtime.

To confirm it's working, you can use mosquitto with a second prepared client
cert to subscribe to the same account and topic, and see and fire messages
at the secure streams connection.

Subscribe:

```
$ mosquitto_sub -h "a1ygonr3im5cv2-ats.iot.us-west-2.amazonaws.com" \
	-p 8883 --cafile ./AmazonRootCA1.pem \
	--cert ./3db6ecc112-certificate.pem.crt \
	--key ./3db6ecc112-private.pem.key\
	-t test/topic0
```

When you run the ss example, you'll see the unix time JSON sent every few secs

```
Client mosq-Ttqhv0VrtSBE0PyDMD received PUBLISH
(d0, q0, r0, m0, 'test/topic0', ... (23 bytes))
{"unixtime":1575814577}
```

Publish:

```
$ mosquitto_pub -h "a1ygonr3im5cv2-ats.iot.us-west-2.amazonaws.com" \
	-p 8883 --cafile ./AmazonRootCA1.pem \
	--cert ./3db6ecc112-certificate.pem.crt \
	--key ./3db6ecc112-private.pem.key \
	-t test/topic0 -m "hello"
```


## build

```
 $ cmake . && make
```

## usage

Commandline option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d15

```
[2019/12/08 14:16:04:0687] U: LWS secure streams [-d<verb>] [-f] [-p] [--h1post]
[2019/12/08 14:16:04:3372] E: callback_ntpc: set up system ops for set_clock
[2019/12/08 14:16:04:5217] N: lws_create_context: creating Secure Streams policy
[2019/12/08 14:16:04:5231] N: _lwsac_use: alloc 1564 for 1
[2019/12/08 14:16:04:5405] N: string1: default
[2019/12/08 14:16:04:5491] N: string1: amazon_root_ca_1
[2019/12/08 14:16:04:5551] N: string1: starfield_services_root_ca
[2019/12/08 14:16:04:5564] N: string1: starfield_class_2_ca
[2019/12/08 14:16:04:5613] N: lws_ss_policy_parser_cb: trust stores stack amazon_root_ca_1
[2019/12/08 14:16:04:5621] N: lws_ss_policy_parser_cb: trust stores stack starfield_services_root_ca
[2019/12/08 14:16:04:5622] N: lws_ss_policy_parser_cb: trust stores stack starfield_class_2_ca
[2019/12/08 14:16:04:5627] N: string1: mqtt_test
[2019/12/08 14:16:04:5713] N: lws_ss_policy_set: policy lwsac size:     1.540KiB, pad 58%
[2019/12/08 14:16:04:5723] N: lws_ss_policy_set: mqtt_amz_iot
[2019/12/08 14:16:05:4132] N: callback_ntpc: Unix time: 1575814567
[2019/12/08 14:16:05:4185] E: lws_ss_create: unknown stream type api_amazon_com_auth
[2019/12/08 14:16:05:4189] N: lws_ss_sys_auth_api_amazon_com: failed to create LWA auth ss, assuming not needed
[2019/12/08 14:16:05:4192] E: lws_ss_create: unknown stream type api_amazon_com_auth
[2019/12/08 14:16:05:4193] N: lws_ss_sys_auth_api_amazon_com: failed to create LWA auth ss, assuming not needed
[2019/12/08 14:16:05:4196] N: system_notify_cb: operational
[2019/12/08 14:16:05:4228] U: myss_state: LWSSSCS_CREATING, ord 0x0
[2019/12/08 14:16:05:4234] U: myss_state: LWSSSCS_POLL, ord 0x0
[2019/12/08 14:16:05:4242] N: lws_ss_client_connect: using tls
[2019/12/08 14:16:05:4256] N: secstream_connect_munge_mqtt
[2019/12/08 14:16:05:4268] N: lws_ss_client_connect: connecting MQTT, 'x-amzn-mqtt-ca' 'a1ygonr3im5cv2-ats.iot.us-west-2.amazonaws.com'
[2019/12/08 14:16:05:4271] U: myss_state: LWSSSCS_CONNECTING, ord 0x0
[2019/12/08 14:16:05:4318] N: lws_mqtt_generate_id: User space provided a client ID 'lwsMqttClient'
[2019/12/08 14:16:05:4791] E: lws_getaddrinfo46: getaddrinfo 'a1ygonr3im5cv2-ats.iot.us-west-2.amazonaws.com' says 0
[2019/12/08 14:16:05:5837] N: lws_ssl_client_bio_create: set system client cert 0
[2019/12/08 14:16:06:7630] N: callback_ntpc: LWS_CALLBACK_RAW_CLOSE
[2019/12/08 14:16:06:7240] U: myss_state: LWSSSCS_CONNECTED, ord 0x0
[2019/12/08 14:16:07:7992] N: _lws_mqtt_rx_parser: cmd_completion: SUBACK
[2019/12/08 14:16:12:7309] N: myss_tx: sending '{"unixtime":1575814572}'
[2019/12/08 14:16:12:7896] N: _lws_mqtt_rx_parser: cmd_completion: PUBLISH
[2019/12/08 14:16:12:7937] U: myss_rx: len 23, flags: 3
[2019/12/08 14:16:12:7958] N:
[2019/12/08 14:16:12:7980] N: 0000: 7B 22 75 6E 69 78 74 69 6D 65 22 3A 31 35 37 35    {"unixtime":1575
[2019/12/08 14:16:12:7991] N: 0010: 38 31 34 35 37 32 7D                               814572}
[2019/12/08 14:16:12:7994] N:
[2019/12/08 14:16:17:7287] N: myss_tx: sending '{"unixtime":1575814577}'
[2019/12/08 14:16:17:7713] N: _lws_mqtt_rx_parser: cmd_completion: PUBLISH
[2019/12/08 14:16:17:7717] U: myss_rx: len 23, flags: 3
[2019/12/08 14:16:17:7718] N:
[2019/12/08 14:16:17:7724] N: 0000: 7B 22 75 6E 69 78 74 69 6D 65 22 3A 31 35 37 35    {"unixtime":1575
[2019/12/08 14:16:17:7730] N: 0010: 38 31 34 35 37 37 7D                               814577}
[2019/12/08 14:16:17:7732] N:
...
[2019/12/08 14:23:44:6245] N: _lws_mqtt_rx_parser: cmd_completion: PUBLISH
[2019/12/08 14:23:44:6278] U: myss_rx: len 5, flags: 3
[2019/12/08 14:23:44:6299] N:
[2019/12/08 14:23:44:6361] N: 0000: 68 65 6C 6C 6F                                     hello
[2019/12/08 14:23:44:6368] N:
...
```
