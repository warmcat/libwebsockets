# lws minimal raw wol

This example shows how to send a Wake On Lan magic packet to a given mac.

## build

```
 $ cmake . && make
```

## usage

```
$ bin/lws-minimal-raw-wol b4:2e:99:a9:22:90
[2023/11/09 12:25:24:2255] N: lws_create_context: LWS: 4.3.99-v4.3.0-295-g60d671c7, NET CLI SRV H1 H2 WS SS-JSON-POL ConMon ASYNC_DNS IPv6-absent
[2023/11/09 12:25:24:2256] N: __lws_lc_tag:  ++ [wsi|0|pipe] (1)
[2023/11/09 12:25:24:2256] N: __lws_lc_tag:  ++ [vh|0|netlink] (1)
[2023/11/09 12:25:24:2256] N: __lws_lc_tag:  ++ [vh|1|system||-1] (2)
[2023/11/09 12:25:24:2257] N: __lws_lc_tag:  ++ [wsisrv|0|system|asyncdns] (1)
[2023/11/09 12:25:24:2257] N: __lws_lc_tag:  ++ [wsisrv|1|system|asyncdns] (2)
[2023/11/09 12:25:24:2257] N: __lws_lc_tag:  ++ [vh|2|default||0] (3)
[2023/11/09 12:25:24:2257] N: [vh|2|default||0]: lws_socket_bind: source ads 0.0.0.0
[2023/11/09 12:25:24:2257] N: __lws_lc_tag:  ++ [wsi|1|listen|default||33749] (2)
[2023/11/09 12:25:24:2257] N: lws_wol: Sending WOL to B4:2E:99:A9:22:90
[2023/11/09 12:25:24:2258] N: __lws_lc_untag:  -- [wsi|0|pipe] (1) 190μs
[2023/11/09 12:25:24:2258] N: __lws_lc_untag:  -- [wsi|1|listen|default||33749] (0) 80μs
[2023/11/09 12:25:24:2258] N: __lws_lc_untag:  -- [wsisrv|1|system|asyncdns] (1) 118μs
[2023/11/09 12:25:24:2258] N: __lws_lc_untag:  -- [wsisrv|0|system|asyncdns] (0) 155μs
[2023/11/09 12:25:24:2258] N: __lws_lc_untag:  -- [vh|0|netlink] (2) 198μs
[2023/11/09 12:25:24:2258] N: __lws_lc_untag:  -- [vh|1|system||-1] (1) 182μs
[2023/11/09 12:25:24:2258] N: __lws_lc_untag:  -- [vh|2|default||0] (0) 125μs

$
```