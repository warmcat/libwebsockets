# lws minimal http server with multithreaded service

## build

```
 $ cmake . && make
```

## usage

```
 $ ./lws-minimal-http-server-smp
[2018/03/07 17:44:20:2409] USER: LWS minimal http server SMP | visit http://localhost:7681
[2018/03/07 17:44:20:2410] NOTICE: Creating Vhost 'default' port 7681, 1 protocols, IPv6 on
[2018/03/07 17:44:20:2411] NOTICE:   Service threads: 10
```

Visit http://localhost:7681 and use ab or other testing tools

