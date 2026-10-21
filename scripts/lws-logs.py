#!/usr/bin/env python3
"""Use an lws-log-ingest api, see READMEs/README.log-ship.md.

usage: lws-logs.py [--creds FILE] [--auth URL] [--service NAME] <api> <cmd>

  <api>   the url of the api mount, eg, https://example.com/logs/api
  <cmd>   one of

    get <path>       GET <api>/<path>, eg, 'sessions', 'sources',
                     'logs?session=<id>&lvl=warn', 'sync?session=<id>'
    start [--from F] [--duration S] [--lvl L] [--src P] [--note N]
                     start a session: F is UTC ISO 8601, epoch ms or -<secs>
                     before now (default now); S seconds (default 600); L one
                     of err, warn, notice, info, debug, the level the
                     shippers log at for the session; P comma-separated
                     patterns of the kinds or hosts it's for (default all)
    stop <id>        end a session early

The JSON answer goes to stdout.  The account needs the api's grant.

--creds FILE, or $LWS_LOGS_CREDS, is a file of the account's username on its
first line, its password on its second, and its base32 TOTP secret on a later
line, either alone or after ": ".  None of it is printed.

--auth URL, or $LWS_LOGS_AUTH, is the auth server the site's lws-login uses.

--service NAME, or $LWS_LOGS_SERVICE, is the grant the api's mount is guarded
by, lws-logs by default.

The site's session cookie is kept in ~/.cache/lws-logs/, readable only by
you, and reused until it stops working.  Only then does this log in again,
once, stopping at the first refusal, since the auth server counts failed
logins against the account.
"""

import base64
import hashlib
import hmac
import http.cookiejar
import json
import os
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


def usage(why=None):
    if why:
        sys.stderr.write("lws-logs.py: %s\n" % why)
    sys.stderr.write(__doc__)
    sys.exit(1)


def creds(path):
    with open(os.path.expanduser(path)) as f:
        ls = [l.rstrip("\r\n") for l in f]
    if len(ls) < 3:
        usage("%s: wants username, password and TOTP secret lines" % path)
    sec = ls[2:]
    sec = [l.rsplit(": ", 1)[-1].strip() for l in sec if l.strip()]
    if not sec:
        usage("%s: no TOTP secret line" % path)
    return ls[0].strip(), ls[1], sec[-1]


def totp(secret):
    k = base64.b32decode(secret.upper().replace(" ", "") +
                         "=" * (-len(secret) % 8))
    h = hmac.new(k, struct.pack(">Q", int(time.time()) // 30),
                 hashlib.sha1).digest()
    o = h[-1] & 15
    return "%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff) %
                     1000000)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def opener(jar, follow=True):
    hs = [urllib.request.HTTPCookieProcessor(jar)]
    if not follow:
        hs.append(NoRedirect())
    return urllib.request.build_opener(*hs)


def req(op, url, data=None, origin=None, ctype=None):
    r = urllib.request.Request(url, data=data)
    if origin:
        r.add_header("Origin", origin)
    if data is not None:
        r.add_header("Content-Type",
                     ctype or "application/x-www-form-urlencoded")
    try:
        with op.open(r, timeout=60) as resp:
            return resp.status, resp.headers, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()


def login(jar, auth, service, credpath, api, target):
    user, pw, sec = creds(credpath)
    op = opener(jar)

    st, _, body = req(op, auth + "/api/status?service_name=" + service)
    if st != 200:
        sys.exit("%s/api/status: %d" % (auth, st))
    csrf = json.loads(body).get("csrf_token", "")

    form = urllib.parse.urlencode({
        "username": user, "password": pw, "totp": totp(sec),
        "csrf_token": csrf, "redirect_uri": target,
        "service_name": service}).encode()
    st, hd, body = req(op, auth + "/api/login", form)
    if st != 200:
        try:
            why = json.loads(body).get("error", "")
        except ValueError:
            why = ""
        sys.exit("%s/api/login: %d %s%s" % (auth, st, why,
                 " (wants TOTP)" if hd.get("X-Requires-TOTP") else ""))
    tok = json.loads(body).get("token")
    if not tok:
        sys.exit("%s/api/login: no token in the answer" % auth)

    # hand it to the site's lws-login as the auth page's form would, which
    # comes from the auth server's origin
    sso = api + "/.lws-login-sso"
    st, _, _ = req(opener(jar, False), sso, urllib.parse.urlencode(
        {"token": tok, "target": target}).encode(), auth)
    if st not in (200, 302, 303):
        sys.exit("%s: %d" % (sso, st))


def session_body(a):
    opts = {"--from": "from", "--duration": "duration", "--lvl": "lvl",
            "--src": "src", "--note": "note"}
    b = {}
    while a:
        if len(a) < 2 or a[0] not in opts:
            usage("start takes --from, --duration, --lvl, --src, --note")
        k = opts[a[0]]
        b[k] = int(a[1]) if k == "duration" else a[1]
        a = a[2:]
    return json.dumps(b).encode()


def main():
    a = sys.argv[1:]
    credpath = os.environ.get("LWS_LOGS_CREDS")
    auth = os.environ.get("LWS_LOGS_AUTH")
    service = os.environ.get("LWS_LOGS_SERVICE", "lws-logs")
    while a and a[0].startswith("--"):
        if len(a) < 2 or a[0] not in ("--creds", "--auth", "--service"):
            usage()
        if a[0] == "--creds":
            credpath = a[1]
        elif a[0] == "--auth":
            auth = a[1]
        else:
            service = a[1]
        a = a[2:]
    if len(a) < 2:
        usage()
    api, cmd, a = a[0].rstrip("/"), a[1], a[2:]

    data = None
    if cmd == "get" and len(a) == 1:
        url = api + "/" + a[0].lstrip("/")
    elif cmd == "start":
        url = api + "/sessions"
        data = session_body(a)
    elif cmd == "stop" and len(a) == 1:
        url = api + "/sessions/%s/stop" % urllib.parse.quote(a[0])
        data = b"{}"
    else:
        usage()

    host = urllib.parse.urlparse(api).netloc
    d = os.path.expanduser("~/.cache/lws-logs")
    os.makedirs(d, mode=0o700, exist_ok=True)
    os.umask(0o077)
    path = os.path.join(d, "cookies-%s.txt" % host)
    jar = http.cookiejar.MozillaCookieJar(path)
    if os.path.exists(path):
        jar.load(ignore_discard=True, ignore_expires=True)

    def go():
        # lws-login sends a request with no session to log in: we don't
        # follow it, that's our cue to log in ourselves
        return req(opener(jar, False), url, data, None,
                   "application/json" if data is not None else None)

    st, _, body = go()
    if st in (302, 303, 307, 401, 403):
        if not credpath or not auth:
            usage("%d, and no --creds and --auth to log in with" % st)
        # after logging in, land somewhere harmless to GET
        login(jar, auth.rstrip("/"), service, credpath, api,
              api + "/sessions")
        # keep the session now, so a failure after doesn't cost a login
        jar.save(ignore_discard=True, ignore_expires=True)
        st, _, body = go()
    jar.save(ignore_discard=True, ignore_expires=True)
    if st != 200:
        sys.exit("%s: %d %s" % (url, st, body[:300].decode(errors="replace")))
    sys.stdout.buffer.write(body)


main()
