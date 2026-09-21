#!/usr/bin/env python3
#
# ctest fixture for lws-api-test-ws-close: a minimal http CONNECT proxy and
# SOCKS5 proxy in one process, so the client proxy connect states can be
# exercised without external infrastructure.
#
#   proxy-fixture.py --port P [--auth-port Q] [ignored args...]
#
# Port P accepts both "CONNECT host:port HTTP/1.1" and SOCKS5 with the
# no-authentication method.  Port Q, if given, is SOCKS5 selecting the
# username/password method and only accepting user "user", password "pass".
# Anything after the handshake is relayed byte for byte in both directions.
# Extra args (ctest-background.sh appends -d1039) are ignored.

import socket, sys, threading, select

def relay(a, b):
    socks = [a, b]
    try:
        while True:
            r, _, _ = select.select(socks, [], [], 30)
            if not r:
                break
            for s in r:
                d = s.recv(65536)
                if not d:
                    return
                (b if s is a else a).sendall(d)
    except OSError:
        pass
    finally:
        for s in socks:
            try:
                s.close()
            except OSError:
                pass

def recv_exact(c, n):
    buf = b""
    while len(buf) < n:
        d = c.recv(n - len(buf))
        if not d:
            raise OSError("eof")
        buf += d
    return buf

def socks5(c, require_auth):
    ver, nm = recv_exact(c, 2)
    methods = recv_exact(c, nm)
    if ver != 5:
        raise OSError("not socks5")
    if require_auth:
        if 2 not in methods:
            c.sendall(b"\x05\xff")
            raise OSError("client did not offer user/pass")
        c.sendall(b"\x05\x02")
        sv, ul = recv_exact(c, 2)
        user = recv_exact(c, ul)
        pl = recv_exact(c, 1)[0]
        pw = recv_exact(c, pl)
        if sv != 1 or user != b"user" or pw != b"pass":
            c.sendall(b"\x01\x01")
            raise OSError("bad credentials")
        c.sendall(b"\x01\x00")
    else:
        if 0 not in methods:
            c.sendall(b"\x05\xff")
            raise OSError("client did not offer no-auth")
        c.sendall(b"\x05\x00")
    ver, cmd, _, atyp = recv_exact(c, 4)
    if ver != 5 or cmd != 1:
        c.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
        raise OSError("not a CONNECT")
    if atyp == 1:
        host = socket.inet_ntoa(recv_exact(c, 4))
    elif atyp == 3:
        host = recv_exact(c, recv_exact(c, 1)[0]).decode()
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, recv_exact(c, 16))
    else:
        raise OSError("bad atyp")
    port = int.from_bytes(recv_exact(c, 2), "big")
    up = socket.create_connection((host, port), timeout=10)
    c.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
    return up

def http_connect(c, first):
    buf = first
    while b"\r\n\r\n" not in buf:
        d = c.recv(4096)
        if not d:
            raise OSError("eof in CONNECT")
        buf += d
    line = buf.split(b"\r\n", 1)[0].decode()
    parts = line.split()
    if len(parts) < 2 or parts[0] != "CONNECT":
        c.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
        raise OSError("not a CONNECT: " + line)
    host, _, port = parts[1].rpartition(":")
    host = host.strip("[]")
    up = socket.create_connection((host, int(port)), timeout=10)
    c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
    return up

def serve(c, require_auth):
    up = None
    try:
        c.settimeout(10)
        first = c.recv(1, socket.MSG_PEEK)
        if first == b"\x05":
            up = socks5(c, require_auth)
        elif require_auth:
            raise OSError("auth port only speaks socks5")
        else:
            up = http_connect(c, c.recv(4096))
        c.settimeout(None)
        relay(c, up)
    except OSError as e:
        sys.stderr.write("fixture: %s\n" % e)
        c.close()
        if up:
            up.close()

def listen(port, require_auth):
    l = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    l.bind(("127.0.0.1", port))
    l.listen(16)
    while True:
        c, _ = l.accept()
        threading.Thread(target=serve, args=(c, require_auth),
                         daemon=True).start()

def main():
    port = auth_port = None
    a = sys.argv[1:]
    while a:
        if a[0] == "--port":
            port = int(a[1]); a = a[2:]
        elif a[0] == "--auth-port":
            auth_port = int(a[1]); a = a[2:]
        else:
            a = a[1:]
    if port is None:
        sys.exit("--port required")
    if auth_port is not None:
        threading.Thread(target=listen, args=(auth_port, True),
                         daemon=True).start()
    listen(port, False)

if __name__ == "__main__":
    main()
