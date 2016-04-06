Libwebsockets Web Server
------------------------

lwsws is an implementation of a very lightweight, ws-capable generic web
server, which uses libwebsockets to implement everything underneath.

Build
-----

Just enable -DLWS_WITH_LWSWS=1 at cmake-time.

It enables libuv and plugin support automatically.


Configuration
-------------

lwsws uses JSON config files, there is a single file intended for global
settings

/etc/lwsws/conf

```
# these are the server global settings
# stuff related to vhosts should go in one
# file per vhost in ../conf.d/

{
  "global": {
   "uid": "99",
   "gid": "99",
   "interface": "eth0",
   "count-threads": "1",
   "init-ssl": "yes"
 }
}
```

and a config directory intended to take one file per vhost

/etc/lwsws/conf.d/warmcat.com

```
{
	"vhosts": [{
		"name": "warmcat.com",
		"port": "443",
		"host-ssl-key": "/etc/pki/tls/private/warmcat.com.key",
		"host-ssl-cert": "/etc/pki/tls/certs/warmcat.com.crt",
		"host-ssl-ca": "/etc/pki/tls/certs/warmcat.com.cer",
		"mounts": [{
			"mountpoint": "/",
			"origin": "file:///var/www/warmcat.com",
			"default": "index.html"
		}]
	}]
}
```

Vhosts
------

One server can run many vhosts, where SSL is in use SNI is used to match
the connection to a vhost and its vhost-specific SSL keys during SSL
negotiation.

Listing multiple vhosts looks something like this

```
{
        "vhosts": [{
                "name": "warmcat.com",
                "port": "443",
                "host-ssl-key": "/etc/pki/tls/private/warmcat.com.key",
                "host-ssl-cert": "/etc/pki/tls/certs/warmcat.com.crt",
                "host-ssl-ca": "/etc/pki/tls/certs/warmcat.com.cer",
                "mounts": [{
                        "mountpoint": "/",
                        "origin": "file:///var/www/warmcat.com",
                        "default": "index.html"
                }]
        }, {
                "name": "warmcat2.com",
                "port": "443",
                "host-ssl-key": "/etc/pki/tls/private/warmcat.com.key",
                "host-ssl-cert": "/etc/pki/tls/certs/warmcat.com.crt",
                "host-ssl-ca": "/etc/pki/tls/certs/warmcat.com.cer",
                "mounts": [{
                        "mountpoint": "/",
                        "origin": "file:///var/www/warmcat2.com",
                        "default": "index.html"
                }]
        }
]
}
```

Vhost name and port
-------------------

The vhost name field is used to match on incoming SNI or Host: header, so it
must always be the host name used to reach the vhost externally.

Vhosts may have the same name and different ports, these will each create a
listening socket on the appropriate port.

They may also have the same port and different name: these will be treated as
true vhosts on one listening socket and the active vhost decided at SSL
negotiation time (via SNI) or if no SSL, then after the Host: header from
the client has been parsed.


Mounts
------

Where mounts are given in the vhost definition, then directory contents may
be auto-served if it matches the mountpoint.

Currently only file:// mount protocol and a fixed set of mimetypes are
supported.


Plugins
-------

Protcols and extensions may also be provided from "plugins", these are
lightweight dynamic libraries.  They are scanned for at init time, and
any protocols and extensions found are added to the list given at context
creation time.

Protocols receive init (LWS_CALLBACK_PROTOCOL_INIT) and destruction
(LWS_CALLBACK_PROTOCOL_DESTROY) callbacks per-vhost, and there are arrangements
they can make per-vhost allocations and get hold of the correct pointer from
the wsi at the callback.

This allows a protocol to choose to strictly segregate data on a per-vhost
basis, and also allows the plugin to handle its own initialization and
context storage.

To help that happen conveniently, there are some new apis

 - lws_vhost_get(wsi)
 - lws_protocol_get(wsi)
 - lws_callback_on_writable_all_protocol_vhost(vhost, protocol)
 - lws_protocol_vh_priv_zalloc(vhost, protocol, size)
 - lws_protocol_vh_priv_get(vhost, protocol)
 
dumb increment, mirror and status protocol plugins are provided as examples.


