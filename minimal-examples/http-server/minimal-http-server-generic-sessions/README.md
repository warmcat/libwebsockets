# lws minimal http server with generic-sessions

## build

```
 $ cmake . && make
```

## usage

```
 $ ./lws-minimal-http-server-tls
[2018/03/20 13:23:13:0131] USER: LWS minimal http server TLS | visit https://localhost:7681
[2018/03/20 13:23:13:0142] NOTICE: Creating Vhost 'default' port 7681, 1 protocols, IPv6 off
[2018/03/20 13:23:13:0142] NOTICE:  Using SSL mode
[2018/03/20 13:23:13:0146] NOTICE:  SSL ECDH curve 'prime256v1'
[2018/03/20 13:23:13:0146] NOTICE:  HTTP2 / ALPN enabled
[2018/03/20 13:23:13:0195] NOTICE: lws_tls_client_create_vhost_context: doing cert filepath localhost-100y.cert
[2018/03/20 13:23:13:0195] NOTICE: Loaded client cert localhost-100y.cert
[2018/03/20 13:23:13:0195] NOTICE: lws_tls_client_create_vhost_context: doing private key filepath
[2018/03/20 13:23:13:0196] NOTICE: Loaded client cert private key localhost-100y.key
[2018/03/20 13:23:13:0196] NOTICE: created client ssl context for default
[2018/03/20 13:23:14:0207] NOTICE:    vhost default: cert expiry: 730459d
```


