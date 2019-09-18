# lws minimal ws client PING

This connects to libwebsockets.org using the lws-mirror-protocol.

It then sends a ws PING every 5s and records any PONG coming back.

## build

```
 $ cmake . && make
```

## Commandline Options

Option|Meaning
---|---
-d|Set logging verbosity
--server|Use a specific server instead of libwebsockets.org, eg `--server localhost`.  Implies LCCSCF_ALLOW_SELFSIGNED
--port|Use a specific port instead of 443, eg `--port 7681`
-z|Send zero-length pings for testing
--protocol|Use a specific ws subprotocol rather than lws-mirror-protocol, eg, `--protocol myprotocol`
-v|Connection validity use 3s / 10s instead of default 5m / 5m10s


## usage

Just run it, wait for the connect and then there will be PINGs sent
at 5s intervals.

```
 $ ./lws-minimal-ws-client-ping
[2018/05/09 16:55:03:1160] USER: LWS minimal ws client PING
[2018/05/09 16:55:03:1379] NOTICE: Creating Vhost 'default' (serving disabled), 1 protocols, IPv6 off
[2018/05/09 16:55:03:1715] NOTICE: client loaded CA for verification ./libwebsockets.org.cer
[2018/05/09 16:55:03:1717] NOTICE: created client ssl context for default
[2018/05/09 16:55:04:8332] USER: callback_minimal_broker: established
[2018/05/09 16:55:09:8389] USER: Sending PING 10...
[2018/05/09 16:55:10:1491] USER: LWS_CALLBACK_CLIENT_RECEIVE_PONG
[2018/05/09 16:55:10:1494] NOTICE: 
[2018/05/09 16:55:10:1514] NOTICE: 0000: 70 69 6E 67 20 62 6F 64 79 21                      ping body!      
[2018/05/09 16:55:10:1515] NOTICE: 
...
```

