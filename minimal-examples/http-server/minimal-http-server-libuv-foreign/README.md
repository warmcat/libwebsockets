# lws minimal http server libuv foreign

This demonstrates having lws take part in a libuv loop owned by
something else, with its own objects running in the loop.

Lws can join the loop, and clean up perfectly after itself.

## build

```
 $ cmake . && make
```

## usage

```
 $ ./lws-minimal-http-server-libuv-foreign
[2018/03/29 12:19:31:3480] USER: LWS minimal http server libuv + foreign loop | visit http://localhost:7681
[2018/03/29 12:19:31:3724] NOTICE: Creating Vhost 'default' port 7681, 1 protocols, IPv6 off
[2018/03/29 12:19:31:3804] NOTICE:  Using foreign event loop...
[2018/03/29 12:19:31:3938] USER: Foreign 1Hz timer
[2018/03/29 12:19:32:4011] USER: Foreign 1Hz timer
[2018/03/29 12:19:33:4024] USER: Foreign 1Hz timer
^C[2018/03/29 12:19:33:8868] NOTICE: Signal 2 caught, exiting...
[2018/03/29 12:19:33:8963] USER: main: starting exit cleanup...
[2018/03/29 12:19:33:9064] USER: main: lws context destroyed: cleaning the foreign loop
[2018/03/29 12:19:33:9108] USER: main: exiting...
```

Visit http://localhost:7681

