#!/usr/bin/env python3
#
# ctest fixture for lws-api-test-ws-close: a minimal http CONNECT proxy and
# SOCKS5 proxy in one process, so the client proxy connect states can be
# exercised without external infrastructure.
#
#   proxy-fixture.py --port P [--auth-port Q] [--log FILE] [ignored args...]
#
# Port P accepts both "CONNECT host:port HTTP/1.1" and SOCKS5 with the
# no-authentication method.  Port Q, if given, is SOCKS5 selecting the
# username/password method and only accepting user "user", password "pass".
# Anything after the handshake is relayed byte for byte in both directions.
# Extra args (ctest-background.sh appends -d1039) are ignored.
#
# Every connection is logged as it goes, to stderr and, with --log, to FILE:
# who connected, what it asked for, how long the onward connect took or why
# it failed, and how the relay ended, with the bytes each way.  The tests
# using the fixture take the same FILE as --proxy-log and print it when they
# fail, since ctest only shows a fixture's own output when the fixture fails.
# The timestamps are in the lws log format, so the two can be read together.

import socket, sys, threading, select, time, os

log_lock = threading.Lock()
log_file = None
conn_seq = 0

def stamp():
    t = time.time()
    return "%s:%04d" % (time.strftime("%Y/%m/%d %H:%M:%S", time.localtime(t)),
                        int((t % 1) * 10000))

def log(msg):
    line = "[%s] P: %s\n" % (stamp(), msg)
    with log_lock:
        sys.stderr.write(line)
        sys.stderr.flush()
        if log_file:
            log_file.write(line)
            log_file.flush()

def ms_since(t0):
    return int((time.monotonic() - t0) * 1000)

def relay(cid, a, b, t0):
    socks = [a, b]
    count = {a: 0, b: 0}
    why = "?"
    try:
        while True:
            r, _, _ = select.select(socks, [], [], 30)
            if not r:
                why = "idle 30s"
                break
            for s in r:
                d = s.recv(65536)
                if not d:
                    why = "client closed" if s is a else "upstream closed"
                    return
                count[s] += len(d)
                (b if s is a else a).sendall(d)
    except OSError as e:
        why = "error: %s" % e
    finally:
        log("c%d: relay ended, %s, client->upstream %d, upstream->client "
            "%d, after %dms" % (cid, why, count[a], count[b], ms_since(t0)))
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

def socks5_userpass(c):
    sv, ul = recv_exact(c, 2)
    user = recv_exact(c, ul)
    pl = recv_exact(c, 1)[0]
    pw = recv_exact(c, pl)
    if sv != 1 or user != b"user" or pw != b"pass":
        c.sendall(b"\x01\x01")
        raise OSError("bad credentials")
    c.sendall(b"\x01\x00")

def socks5_greeting(c, require_auth):
    ver, nm = recv_exact(c, 2)
    methods = recv_exact(c, nm)
    if ver != 5:
        raise OSError("not socks5")
    want = 2 if require_auth else 0
    if want not in methods:
        c.sendall(b"\x05\xff")
        raise OSError("client did not offer method %d" % want)
    c.sendall(bytes([5, want]))
    if require_auth:
        socks5_userpass(c)

def upstream(cid, host, port, t0):
    log("c%d: connecting on to %s:%d" % (cid, host, port))
    tu = time.monotonic()
    try:
        up = socket.create_connection((host, port), timeout=10)
    except OSError as e:
        log("c%d: onward connect to %s:%d failed after %dms: %s" %
            (cid, host, port, ms_since(tu), e))
        raise
    log("c%d: onward connect to %s:%d (%s) took %dms" %
        (cid, host, port, up.getpeername()[0], ms_since(tu)))
    return up

def socks5(cid, c, require_auth, t0):
    socks5_greeting(c, require_auth)
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
    log("c%d: socks5%s CONNECT %s:%d, %dms after accept" %
        (cid, " (auth)" if require_auth else "", host, port, ms_since(t0)))
    up = upstream(cid, host, port, t0)
    c.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
    return up

def http_connect(cid, c, first, t0):
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
    log("c%d: http %s, %dms after accept" % (cid, line, ms_since(t0)))
    host, _, port = parts[1].rpartition(":")
    host = host.strip("[]")
    up = upstream(cid, host, int(port), t0)
    c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
    return up

def serve(cid, c, require_auth, t0):
    up = None
    try:
        c.settimeout(10)
        first = c.recv(1, socket.MSG_PEEK)
        if not first:
            raise OSError("client closed before sending anything")
        if first == b"\x05":
            up = socks5(cid, c, require_auth, t0)
        elif require_auth:
            raise OSError("auth port only speaks socks5")
        else:
            up = http_connect(cid, c, c.recv(4096), t0)
        c.settimeout(None)
        log("c%d: tunnel up, %dms after accept" % (cid, ms_since(t0)))
        relay(cid, c, up, t0)
    except OSError as e:
        log("c%d: failed after %dms: %s" % (cid, ms_since(t0), e))
        c.close()
        if up:
            up.close()

def listen(port, require_auth):
    global conn_seq
    l = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    l.bind(("127.0.0.1", port))
    l.listen(16)
    log("pid %d listening on 127.0.0.1:%d%s" %
        (os.getpid(), port, " (socks5 auth)" if require_auth else ""))
    while True:
        c, peer = l.accept()
        t0 = time.monotonic()
        with log_lock:
            conn_seq += 1
            cid = conn_seq
        log("c%d: accepted from %s:%d on port %d" %
            (cid, peer[0], peer[1], port))
        threading.Thread(target=serve, args=(cid, c, require_auth, t0),
                         daemon=True).start()

def main():
    global log_file
    port = auth_port = None
    a = sys.argv[1:]
    while a:
        if a[0] == "--port":
            port = int(a[1]); a = a[2:]
        elif a[0] == "--auth-port":
            auth_port = int(a[1]); a = a[2:]
        elif a[0] == "--log":
            log_file = open(a[1], "w")
            a = a[2:]
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
