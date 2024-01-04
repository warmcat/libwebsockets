# lws minimal http server systemd socketact

## build

```
 $ cmake . && make && sudo make install
```

This will by default install to `/usr/local` and the systemd pieces to `/usr/local/lib/systemd/system`

Assets will go to `/usr/local/share/lws-minimal-http-server-systemd-socketact/` and
the test app will know to fetch things from there.

## configure

```
 $ systemctl --user link /usr/local/lib/systemd/system/lws-minimal-http-server-systemd-socketact.service /usr/local/lib/systemd/system/lws-minimal-http-server-systemd-socketact.socket
 $ systemctl --user start lws-minimal-http-server-systemd-socketact.socket
```

Then the test server should be autoexecuted by systemd if you try to browse to `http://127.0.0.1:7681`


