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

lwsws uses JSON config files, they're pure JSON but # may be used to turn the rest of the line into a comment.

There is a single file intended for global settings

/etc/lwsws/conf

```
# these are the server global settings
# stuff related to vhosts should go in one
# file per vhost in ../conf.d/

{
  "global": {
   "uid": "48",
   "gid": "48",
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
 "vhosts": [ {
     "name": "localhost",
     "port": "443",
     "host-ssl-key":  "/etc/pki/tls/private/libwebsockets.org.key",
     "host-ssl-cert": "/etc/pki/tls/certs/libwebsockets.org.crt",
     "host-ssl-ca":   "/etc/pki/tls/certs/libwebsockets.org.cer",
     "mounts": [{
       "mountpoint": "/",
       "origin": "file:///var/www/libwebsockets.org",
       "default": "index.html"
       }, {
        "mountpoint": "/testserver",
        "origin": "file:///usr/local/share/libwebsockets-test-server",
        "default": "test.html"
       }],
     # which protocols are enabled for this vhost, and optional
     # vhost-specific config options for the protocol
     #
     "ws-protocols": [{
       "warmcat,timezoom": {
         "status": "ok"
       }
     }]
    },
    {
    "name": "localhost",
    "port": "7681",
     "host-ssl-key":  "/etc/pki/tls/private/libwebsockets.org.key",
     "host-ssl-cert": "/etc/pki/tls/certs/libwebsockets.org.crt",
     "host-ssl-ca":   "/etc/pki/tls/certs/libwebsockets.org.cer",
     "mounts": [{
       "mountpoint": "/",
       "origin": ">https://localhost"
     }]
   },
    {
    "name": "localhost",
    "port": "80",
     "mounts": [{
       "mountpoint": "/",
       "origin": ">https://localhost"
     }]
   }

  ]
}
```

That sets up three vhosts all called "localhost" on ports 443 and 7681 with SSL, and port 80 without SSL but with a forced redirect to https://localhost


Vhost name and port
-------------------

The vhost name field is used to match on incoming SNI or Host: header, so it
must always be the host name used to reach the vhost externally.

 - Vhosts may have the same name and different ports, these will each create a
listening socket on the appropriate port.

 - Vhosts may also have the same port and different name: these will be treated as
true vhosts on one listening socket and the active vhost decided at SSL
negotiation time (via SNI) or if no SSL, then after the Host: header from
the client has been parsed.


Protocols
---------

Vhosts by default have available the union of any initial protocols from context creation time, and
any protocols exposed by plugins.

Vhosts can select which plugins they want to offer and give them per-vhost settings using this syntax

```	
     "ws-protocols": [{
       "warmcat,timezoom": {
         "status": "ok"
       }
     }]

```

Other vhost options
-------------------

 - If the three options "host-ssl-cert", "host-ssl-ca" and "host-ssl-key" are given, then the vhost supports SSL.

 Each vhost may have its own certs, SNI is used during the initial connection negotiation to figure out which certs to use by the server name it's asking for from the request DNS name.

 - keeplive-timeout (in secs) defaults to 60 for lwsws, it may be set as a vhost option


Mounts
------

Where mounts are given in the vhost definition, then directory contents may
be auto-served if it matches the mountpoint.

Mount protocols are used to control what kind of translation happens

 - file://  serve the uri using the remainder of the url past the mountpoint based on the origin directory.

 Eg, with this mountpoint

```
       {
        "mountpoint": "/",
        "origin": "file:///var/www/mysite.com",
        "default": "/"
       }
```

 The uri /file.jpg would serve /var/www/mysite.com/file.jpg, since / matched.

 - ^http:// or ^https://  these cause any url matching the mountpoint to issue a redirect to the origin url

 - cgi://   this causes any matching url to be given to the named cgi, eg

```
       {
        "mountpoint": "/git",
        "origin": "cgi:///var/www/cgi-bin/cgit",
        "default": "/"
       }, {
        "mountpoint": "/cgit-data",
        "origin": "file:///usr/share/cgit",
        "default": "/"
       },
```

 would cause the url /git/myrepo to pass "myrepo" to the cgi /var/www/cgi-bin/cgit and send the results to the client.

 When using a cgi:// protcol origin at a mountpoint, you may also give cgi environment variables specific to the mountpoint like this

```
       {
        "mountpoint": "/git",
        "origin": "cgi:///var/www/cgi-bin/cgit",
        "default": "/",
        "cgi-env": [{
                "CGIT_CONFIG": "/etc/cgitrc/libwebsockets.org"
        }]
       }
```

 This allows you to customize one cgi depending on the mountpoint (and / or vhost).

 It's also possible to set the cgi timeout (in secs) per cgi:// mount, like this

```
	"cgi-timeout": "30"
```


Note: currently only a fixed set of mimetypes are supported.


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



