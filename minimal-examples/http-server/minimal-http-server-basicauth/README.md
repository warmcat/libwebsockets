# lws minimal http server basic auth

This demonstrates how to protect a mount using a password
file outside of the mount itself.

The demo has two mounts, a normal one at / and one protected
by basic auth at /secret.

The file at ./ba-passwords contains valid user:password
combinations.

## build

```
 $ cmake . && make
```

## usage

```
 $ ./lws-minimal-http-server-basic-auth
[2018/04/19 08:40:05:1333] USER: LWS minimal http server basic auth | visit http://localhost:7681
[2018/04/19 08:40:05:1333] NOTICE: Creating Vhost 'default' port 7681, 1 protocols, IPv6 off
```

Visit http://localhost:7681, and follow the link there to the secret area.

Give your browser "user" and "password" as the credentials.

