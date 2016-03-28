Libwebsockets Web Server
------------------------

lwsws is an implementation of a very lightweight, ws-capable generic web
server, which uses libwebsockets to implement everything underneath.

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
listening socket on the appropriate port, and they may have the same port and
different name: these will be treated as true vhosts on one listening socket
and the active vhost decided at SSL negotiation time (via SNI) or if no SSL,
then after the Host: header from the client has been parsed.


Mounts
------

Where mounts are given in the vhost definition, then directory contents may
be auto-served if it matches the mountpoint.

Currently only file:// mount protocol and a fixed set of mimetypes are
supported.