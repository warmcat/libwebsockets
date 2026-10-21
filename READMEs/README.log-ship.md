# Log shipping and ingest

## Why

When something goes wrong between several machines, eg, the nodes of a DHT
and the server they talk to, the logs that explain it are spread across all of
them, each in its own journal or file, each on its own clock.  Finding out what
happened means collecting them by hand, if they still exist, and lining them up.

Log shipping lets a process mirror its lws log lines to a log ingestor, which
keeps the lines of many processes on many machines in one sqlite db, in UTC, so
they can be looked at together: by a person in a browser, side by side at the
same instant, or by an agent over a JSON api.

It's off until someone asks for it.  The processes stay connected to the
ingestor, but send nothing until a **session** asks for their lines, from a
UTC time that may be a little in the past, for a limited time, and if wanted,
with more logging than usual while it's open.

## The parts

 - the **shipper**, `lws_log_ship_create()` (`LWS_WITH_LOG_SHIP`), one per
   process, keeps the process' lines and sends them when it's asked to; a
   vhost makes one from its `lws-log-ship` pvos, eg, in lwsws's config
 - the **ingestor**, the `lws-log-ingest` plugin, keeps the shippers'
   connections, decides what they send, stores it and answers the api
 - the **viewer**, the plugin's assets, a page using the api
 - `scripts/lws-logs.py`, using the api from the command line

## What a shipper keeps

Every lws log line the process logs, at whatever level its log context lets
through, from whatever thread, whichever log context it went through and
wherever it was emitted to: stderr, syslog and the journal, a file.  So it's
the same on Linux, Windows and macOS.  What isn't an lws log line, like
coredumps, OOM kills or the service manager restarting the process, isn't
there.

The lines go into a backlog in memory, 4MiB by default, with their UTC time to
the us and a sequence number.  lws's own local time and level prefix are taken
off, anything not printable ASCII becomes `?`, and lines are cut at 1024
chars.  When it's full, the oldest go.  A line stays in the backlog until the
ingestor has stored it, or it's pushed out.

When lws's log spew handling stops emitting lines because there are too many,
the shipper still keeps them: they may be exactly the ones wanted.

A shipper is identified by

 - `kind`: what it is, eg, `lwsws`, up to 32 of `[A-Za-z0-9._-]`
 - `host`: its name, the hostname by default, up to 64 of the same
 - `inst`: 16 random hex chosen when it starts, so a restarted process, or a
   reused host name, can be told apart

## Sessions and windows

A session is

 - `from`: the UTC time of the earliest line wanted.  It may be in the past,
   up to an hour by default, and the lines come from the shippers' backlogs
 - how long it lasts from when it's started, up to an hour by default
 - `src`: which shippers it's for, comma-separated patterns each matching a
   kind or a host, with up to three `*`; everything by default
 - `lvl`: optionally, a level, eg `debug`, that the shippers log at for its
   duration, as well as what they log anyway

The ingestor gives each shipper the union of the windows of the open sessions
that name it.  The shipper sends the lines in its backlog from the window's
start, and every line it logs until the window's end, each once.  If the
window asks for more logging, the process logs more until the window closes,
everywhere it logs to, its journal too; then it goes back to what it was.

Raising the level only affects lines logged from then on: lines in the backlog
were only kept at the level in force when they were logged.  And only levels
built into the library can be raised to: a release build of lws doesn't have
info or debug logs in it.

A window closes by itself at its end, even if the shipper can't hear from the
ingestor, and in any case at most 24h after it was given.

Sessions overlap at no cost: a line is stored once, and a session is just a
window of time and the sources it named.

## A shipper's connection

The shipper keeps a websocket connection to the ingestor, subprotocol
`lws-log-ingest`, retrying with backoff if it can't make it, and pinging it
every 30s.  It must be `wss://`, since the first thing it sends is the shared
secret; `ws://` is only allowed to an address on the same machine.  The
ingestor's certificate is checked like any other client connection on the
vhost.

What's said on it, each a ws text message:

```
-> {"schema":"lws-log-ship-hello","secret":"...","kind":"lwsws",
    "host":"node1","inst":"9f2c1e0a7b3d4c55","lvl":7,"oldest":<us>,
    "v":"<lws version>"}
<- {"schema":"lws-log-ship-start","session":"<id>","from":<us>,
    "until":<us>,"lvl":<LLL_ bits>}
-> {"schema":"lws-log-ship-lines","lines":[{"seq":1041,"t":<us>,"l":4,
    "x":"..."}, ...]}
<- {"schema":"lws-log-ship-ack","seq":1041}
<- {"schema":"lws-log-ship-stop"}
```

Times are UTC us.  `l` is the line's `LLL_` bit.  A batch is up to about 48KiB
of JSON, and only one is outstanding at a time; lines are freed when the ack
for them comes.  A batch lost with the connection, or not acked within 30s, is
sent again, and the ingestor ignores lines it already has.

## Making a shipper

### From a vhost's config

Every vhost has the shipper's `lws-log-ship` protocol, and a vhost given pvos
for it makes the shipper, connecting from that vhost with its client tls
settings.  In lwsws, that's in the vhost's `ws-protocols`, like any protocol's
options:

```
"vhosts": [{
	"name": "dht",
	...
	"enable-client-ssl": "1",
	"ws-protocols": [{
		"lws-log-ship": {
			"url": "wss://logs.example.com/lws-log-ship",
			"secret": "<the ingestor's secret>",
			"kind": "lwsws",
			"backlog-kb": "4096"
		}
	}]
}]
```

pvo|default|what it is
---|---|---
`url`||the ingestor, `wss://`, or `ws://` to this machine
`secret`||shared with the ingestor, up to 256 chars
`kind`|`lws`|what kind of process this is, eg, `lwsws`
`host`|the hostname|the name it ships as
`backlog-kb`|`4096`|how much of its lines it keeps, 1 to 1048576

The config file holds the secret, so keep it readable only by root.  There can
only be one shipper in a process, so only one vhost may have these pvos.  An
application not using lwsws can give them in its vhost's `info.pvo` the same
way.

### In an application

```
struct lws_log_ship_info i;

memset(&i, 0, sizeof(i));
i.vhost		= vh;
i.url		= "wss://logs.example.com/lws-log-ship";
i.secret	= secret;
i.kind		= "my-daemon";

ls = lws_log_ship_create(&i);
```

It's destroyed with its vhost, or by `lws_log_ship_destroy()`.  See
`include/libwebsockets/lws-log-ship.h`.

## The ingestor

The `lws-log-ingest` plugin, on an lwsws vhost:

```
"ws-protocols": [{
	"lws-log-ingest": {
		"status": "ok",
		"database": "/var/lib/lws-log-ingest/logs.sqlite3",
		"secret": "<shared with the shippers>",
		"service": "lws-logs"
	}
}],
"mounts": [{
	"mountpoint": "/logs/api",
	"origin": "callback://lws-log-ingest",
	"interceptor-path": "/lws-login-logs"
}, {
	"mountpoint": "/logs",
	"origin": "file:///usr/local/share/libwebsockets-test-server/lws-log-ingest",
	"default": "index.html",
	"interceptor-path": "/lws-login-logs"
}, {
	"mountpoint": "/lws-login-logs",
	"origin": "callback://lws-login",
	"protocol": "lws-login",
	"pmo": [{ "service-name": "lws-logs" }]
}]
```

The shippers connect to any path that isn't behind the interceptor, eg
`/lws-log-ship`; they're authenticated by the secret, not by lws-login.

A process other than lwsws that loads the plugin must link the shared lws
library, as the plugin does.  Linked to the static one, there are two lws in
the process, each with its own logging, and the ingestor only sees the lines
logged through its own copy: the process' own lines are silently missing.

pvo|default|what it is
---|---|---
`database`||the sqlite db, made if it isn't there
`secret`||shared with the shippers, up to 256 chars
`service`|`lws-logs`|the lws-login grant the api is for
`retention-days`|`14`|lines and sessions older than this go, hourly
`rate-lines`|`12000`|the most lines a shipper may store a minute; past it they're dropped and a line says how many
`max-session-secs`|`3600`|the longest a session may last
`max-past-secs`|`3600`|the furthest in the past a session may start
`own-logs`|`1`|keep this process' own lines too, as kind `lws-log-ingest`, unless it already has a shipper
`trust-login-headers`|`0`|see "Who can use the api"

Whatever a shipper sends is checked as if it came from anywhere: the secret
only says it's one of ours, not that what it says is sane.  A message may be at
most 256KiB; a line must have a single real `LLL_` bit, be printable ASCII of
up to 1024 chars, and be within a day of the ingestor's clock; a shipper whose
`inst` was seen before as a different kind or host is refused.

### Storage

In WAL mode, so something else may read it while the ingestor writes:

```
CREATE TABLE sources (src_id INTEGER PRIMARY KEY, kind TEXT, host TEXT,
		      inst TEXT UNIQUE, first_us INTEGER, last_us INTEGER,
		      lag_us INTEGER);
CREATE TABLE lines (id INTEGER PRIMARY KEY, src_id INTEGER, seq INTEGER,
		    t_us INTEGER, rx_us INTEGER, lvl INTEGER, line TEXT);
CREATE TABLE sessions (id TEXT PRIMARY KEY, created_us INTEGER,
		       from_us INTEGER, until_us INTEGER, stopped_us INTEGER,
		       lvl INTEGER, src TEXT, who TEXT, note TEXT);
```

Each line keeps its shipper's own timestamp, and `rx_us` when the ingestor
stored it.  A source's `lag_us` is the smallest `rx_us - t_us` of its latest
batch: its clock's skew, plus how long its lines waited to go.  Read a
source's times with that in mind.  Lines the ingestor adds itself, eg, to say
some were dropped, have no `seq`.

## The api

Under the api mount, answers are JSON.  Times in queries are UTC ISO 8601
(`2026-10-14T08:01:02Z`, optionally with fractional seconds), epoch ms, or
`-<secs>` before now.  A refusal of a request that was understood says why, as
`{"error":"..."}`.

### Sessions

`GET sessions` lists the latest 50, `GET sessions/<id>` one:

```
{"session":"5e0c2f79a1b4d388","created":"2026-10-14T11:58:05.000000Z",
 "from":"2026-10-14T11:57:05.000000Z","until":"2026-10-14T12:08:05.000000Z",
 "from_us":1791979025000000,"until_us":1791979685000000,"open":true,
 "lvl":1055,"src":"lwsws","who":"agent1","note":"dht stall"}
```

`POST sessions` starts one, with a JSON body, all of it optional, and
`Content-Type: application/json`:

```
{"from":"-60","duration":600,"lvl":"debug","src":"lwsws,ingest*",
 "note":"dht stall"}
```

`from` is now by default, `duration` 600s, `lvl` nothing more than is logged
anyway, `src` everything.  The answer is the new session.

`POST sessions/<id>/stop`, with the body `{}`, ends one early.

Only JSON bodies are taken: a page elsewhere can't make a logged-in browser
send one without asking first, which the ingestor never agrees to.

### Sources

`GET sources` says which shippers are connected, by their source `id`, and
until when each is in a window, and the sources heard from in the last day.

A refusal says why as `{"error":"..."}`.

### Lines

`GET logs`:

arg|what it is
---|---
`session`|the session, whose window and `src` are the defaults
`from`, `to`|the window; without a session, the last 10 minutes
`src`|comma-separated kinds or hosts, up to 8, `*` matches anything
`lvl`|the least important level wanted: `err`, `warn`, `notice`, `info` or `debug`; `notice` and below include user lines
`grep`|a substring (not a regex) the line must contain
`limit`|the most lines to answer with, 2000 by default, at most 10000
`after`|the `next` of the last answer, to get the lines after it

```
{"session":"5e0c2f79a1b4d388","from":"...","to":"...",
 "sources":[{"id":3,"kind":"lwsws","host":"node1","inst":"...","lag_ms":12}],
 "lines":[{"i":41,"t":"2026-10-14T11:58:02.123456Z",
           "t_us":1791979082123456,"src":3,"seq":991,"l":4,"x":"..."}],
 "truncated":true,"next":"1791979082123456:41"}
```

Lines come in UTC order; `i` tells lines of the same time apart.  `l` is the line's `LLL_` bit: 1 err, 2 warn, 4
notice, 8 info, 16 debug, 1024 user.  An answer stops at `limit` lines or
8MiB, with `truncated` true.  `next` is after the last line given, to ask for
the rest with, or, for a window still open, for what came since.

### Around an instant

For looking at every source's lines at the same instant, a pane each, the
viewer asks for what's in a pane a piece at a time.  Times are UTC us.

`GET sync?session=<id>` (or `from=` and `to=`, and `src=`), optionally
`&at=<us>`, says what panes there are:

```
{"session":"...","start_us":...,"end_us":...,"from_us":...,"to_us":...,
 "at_us":...,"running":true,
 "panes":[{"pane":"lwsws/node1","kind":"lwsws","host":"node1",
           "lag_ms":7,"insts":1}, ...]}
```

`start_us` to `end_us` is the window, up to now while it's open; `from_us` to
`to_us` is that padded by 30s.  A pane is a kind and host with lines in it;
`insts` says how many instances of it there were, eg, it restarted.

`GET pane?pane=<kind>/<host>&at=<us>[&before=<n>][&after=<n>]` gives a pane's
lines either side of the instant, up to `before` at or before it and `after`
after it, 150 each by default and at most 500:

```
{"at_us":...,"before":[{"i":581,"t":...,"s":4,"l":4,"x":"..."}],
 "after":[...],"more_before":true,"more_after":false}
```

### Who can use the api

lws-login on the mount decides, by the grant named in its `service-name`,
`lws-logs` above.  It stamps the result on the request, and the ingestor
answers a user of that grant, or a global admin, and refuses everyone else
with 403.  It checks the stamped service is its own `service`, so if the mount
in front of it is missing or for another grant, it refuses.  Sessions record
the `x-lws-login-sub` of who started them.

The stamp is read from inside lwsws, `lws_http_get_onward_header()`, so the
ingestor must be served by the same lwsws as lws-login.  If instead it sits
behind a front end that proxies to it, eg, on a unix socket, set
`trust-login-headers` to read them from the request: then nothing else may be
able to reach the ingestor, since anyone who can could send their own.

Agents use an account given the grant, and log in like a browser:

```
$ scripts/lws-logs.py --creds ~/my-creds --auth https://auth.example.com \
	https://logs.example.com/logs/api start --from -120 --duration 900 \
	--lvl info --src lwsws --note "dht stall"
$ scripts/lws-logs.py https://logs.example.com/logs/api \
	get 'logs?session=5e0c2f79a1b4d388&lvl=warn'
```

see its `--help`.

## The viewer

The plugin's assets, mounted as above, are a page for starting, stopping and
choosing sessions, seeing which shippers are connected, and looking at a
session's lines: every source side by side at one instant, or merged in UTC
order.  `#session=<id>` on its url opens a session, so other pages can link to
one.

## Looking at a DHT

On each DHT node's lwsws, add `lws-log-ship` to the `ws-protocols` of the
vhost with the DHT, as above, and on the server, the ingestor.  Nothing is sent until a session is
started, eg, to see the last two minutes and the next ten of every node, with
the nodes logging at info meanwhile:

```
$ scripts/lws-logs.py ... start --from -120 --duration 600 --lvl info
```
