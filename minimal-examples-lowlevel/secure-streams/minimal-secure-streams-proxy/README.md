# lws minimal secure streams proxy

Operates as a secure streams proxy, by default on a listening unix domain socket
"proxy.ss.lws" in the Linux abstract namespace.

Give -p <port> to have it listen on a specific tcp port instead.

Only processes running as the proxy's own user, or with its group as their
primary group, or as root, may connect to it over the Unix Domain Socket;
`--perms user:group` names a different user and group, and `--perms "*"`
lets any local process use it.  A socket in the abstract namespace has no
filesystem permissions, so the proxy checks each client's credentials
itself; a socket path (`-i /path`) is created owned by the given user:group
with mode 0660 instead.  The tcp listener (-p) has no such check, bind it to
a loopback interface with -i.

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
--perms <user:group>|Who may connect to the proxy UDS, `*` for any local process (default: the proxy's own user and group, and root)

```
[2020/02/26 15:41:27:5768] U: LWS secure streams Proxy [-d<verb>]
[2020/02/26 15:41:27:5770] N: lws_ss_policy_set:     2.064KiB, pad 70%: hardcoded
[2020/02/26 15:41:27:5771] N: lws_tls_client_create_vhost_context: using mem client CA cert 1391
[2020/02/26 15:41:27:8681] N: lws_ss_policy_set:     4.512KiB, pad 15%: updated
[2020/02/26 15:41:27:8682] N: lws_tls_client_create_vhost_context: using mem client CA cert 837
[2020/02/26 15:41:27:8683] N: lws_tls_client_create_vhost_context: using mem client CA cert 1043
[2020/02/26 15:41:27:8684] N: lws_tls_client_create_vhost_context: using mem client CA cert 1167
[2020/02/26 15:41:27:8684] N: lws_tls_client_create_vhost_context: using mem client CA cert 1391
[2020/02/26 15:41:28:4226] N: ss_api_amazon_auth_rx: acquired 567-byte api.amazon.com auth token, exp 3600s
```
