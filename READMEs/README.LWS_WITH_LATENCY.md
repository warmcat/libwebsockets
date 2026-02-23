# cmake option: `LWS_WITH_LATENCY`

```
cmake .. -DLWS_WITH_LATENCY=1
```

## Function

Enabling this cmake build option causes:

 - instrumentation to be built into lws that measures how long every service blocks the event loop (this works on all the event libs as well as the default event loop)
 - builds a plugin `protocol_lws_latency` which allows realtime monitoring of the worst latencies

Notice that this measures how long the event loop is blocked for in your system with your user code.  It doesn't measure packet arrival to handling interval.

## Building the plugins

You also need to enable `-DLWS_WITH_PLUGINS=1` to build the plugins, and to do `sudo make install` to install the plugins and  the web assets.

## Setting up the monitoring plugin - code

 - you will need to add a pvo for the plugin with name "lws-latency" and value "ok".
 - you will need to add a mount to your existing vhost, or add a vhost bound to lo only and add the mount there, to serve the web assets / JS. The necessary files are installed into /usr/local/share/libwebsockets-test-server/lws-latency by default so the mount should set it's origin there.  Typically the mountpoint would be `/latency` and it's a file type mountpoint.  The default file there should be `index.html`

## Setting up the monitoring plugin - via lwsws

This is lwsws configuration to run the lws-latency UI plugin on lo without tls.

After starting `sudo lwsws` with this config, you should be able to browse to http://127.0.0.1/latency and get a live display of the current and worst latencies.

### /etc/lwsws/conf


```
{
  "global": {
   "uid": "48",
   "gid": "48",
   "interface": "lo",
   "server-string": "lwsws",
   "init-ssl": "no",
   "timeout-secs": "50",
   "rlimit-nofile": "10000",
   "count-async-threads": 4
 }
}
```

### /etc/lwsws/conf.d/lo

```
{
        "vhosts": [{
                "name": "lo",
                "port": "80",
                "disable-no-protocol-ws-upgrades": "on",
                "enable-client-ssl": "on",
                "ws-protocols": [{
                        "lws-latency": {
                                "status": "ok"
                        }
                 }],
                "mounts": [{
                        "mountpoint": "/latency",
                        "origin": "file://_lws_ddir_/libwebsockets-test-server/lws-latency",
                        "default": "index.html"
                }]
         }
}
```
