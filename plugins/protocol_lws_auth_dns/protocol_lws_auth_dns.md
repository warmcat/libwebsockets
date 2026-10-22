# lws auth dns plugin

## Introduction

The `protocol_lws_auth_dns` plugin provides an authoritative DNS server for
`libwebsockets`, built on the `lws-auth-dns` zone parser / signer and the
DNSSEC library components.  It serves signed zones over both UDP and TCP.

The registered protocol name is **`protocol-lws-auth-dns`**; that is the name
to use for the vhost `ws-protocols` entry and for `listen-accept-protocol`.

The plugin is bound to a vhost and takes its port from that vhost's `port`
(typically 53).  Two listeners result:

 - the vhost's own TCP listener, created by lws core, which must be configured
   to adopt accepted connections as `raw-skt` with this protocol so that DNS
   over TCP (RFC 7766 framing) is served, and
 - IPv4 and IPv6 UDP sockets on the same port, which the plugin itself binds
   during `LWS_CALLBACK_PROTOCOL_INIT`.

Zones come from two sources:

 - **local disk**: `.zone` files in the configured `zone-dir` are scanned once
   at vhost initialization and parsed with `lws_auth_dns_parse_zone_buf()`, and
 - **the DHT**: when the `lws-dht-dnssec` protocol is also enabled on the
   vhost, queries for zones not currently in memory are suspended while the
   zone is fetched from the DHT and verified against the DNSSEC chain, then
   answered from the fetched zone.  DHT-fetched zones live in memory only;
   they are never written into `zone-dir`.  A zone handed over from the DHT
   is only installed if it has an `RRSIG` over its SOA and all its `RRSIG`s
   are in their validity period, and it is held until the earliest expires.
   Since queries arrive over UDP from any, possibly forged, source, a query
   only starts a fetch if its zone is not already being fetched, and only
   once every other limit on suspended queries (below) let it through.  Each
   source host (an IPv4 address, or an IPv6 /64) may start 4 fetches at once,
   then one per 2s, and the vhost as a whole 32 at once, then one per 250ms,
   tracking the 256 hosts seen most recently; a query over that is answered
   `REFUSED` at once.  So one source, or one forged source address, can't
   use up the fetches other sources' queries need.

Incoming queries are matched by `QNAME`, `QTYPE` and `QCLASS` against the loaded
zones and answered `NOERROR` with the authoritative RRsets (and their `RRSIG`s
when `DO` is set).  A name in a zone we hold but with no data for that type is a
`NODATA` answer; a name in no zone we hold, and that the DHT cannot supply, is
answered `REFUSED` per authoritative-server convention.

Zone files are RFC 1035 master files, with `$ORIGIN` and `$TTL` directives
(any other directive refuses the zone).  Owner names may use the RFC 1035
5.1 escapes `\X` and `\DDD` (rdata may not, except for the RFC 3597 `\#`
form), and
names may have `*` as the whole leftmost label, eg, a wildcard owner or an NS
target.  A zone is refused, with an error naming the line,
if a name in it has an empty label anywhere but the root (eg, `.x` or `a..b`),
a `*` anywhere else, a label over 63 bytes, is over 255 bytes in all, or has a
label that could only be written with an escape (a `.` inside a label,
whitespace, quotes, parentheses, `;`, `\` or a non-printable byte), which
auth-dns does not carry.  RRsets at a wildcard owner are served for queries of
that owner name itself; answers are not synthesized from them for the names
the wildcard would match (RFC 4592).

## Scalability and Caching

To serve high query volumes without unbounded memory use, the plugin keeps a
bounded in-memory LRU cache of parsed zones.  When integrated with
`lws-dht-dnssec`, the DHT's own hashed store is the long-term disk cache and
only currently-active zones are pulled into memory.

 - **LRU eviction**: the DHT-fetched zones held are bounded by the
   `cache-max-zones` PVO (default 1000).  When exceeded, the least recently
   queried of them are freed.  Zones loaded from `zone-dir` are the
   operator's: they are always held and served, are never evicted to make
   room, and do not count against `cache-max-zones`.  A newer serial of such
   a zone arriving from the DHT replaces it in memory and is held the same
   way.
 - **Expiry eviction**: a periodic timer purges zones whose SOA-derived TTL
   expiry or DNSSEC `RRSIG` validity has passed.  This is in memory only.

The plugin only ever reads `zone-dir`: it never deletes, rewrites or creates
files there, whatever happens to its in-memory copies.  Replacing an expired
or superseded zone file is up to the operator.

Zone updates are serial-gated: a replacement zone whose SOA serial is not newer
(RFC 1982 comparison) than the one already held is rejected, so a replayed
older zone cannot displace a current one.

## Negative Answers and NSEC3

When a query with the DNSSEC `DO` bit set does not match a record in a served
zone, the authority section carries the zone `SOA` and, per RFC 5155 §7.2, only
the NSEC3 RRs that actually deny the name:

 - the NSEC3 matching the *closest encloser*,
 - the NSEC3 *covering* the next closer name, and
 - the NSEC3 *covering* the wildcard at the closest encloser,

deduplicated (one NSEC3 often covers two of these), each followed by its
`RRSIG`.  For a `NODATA` answer — the name exists but the type does not — only
the NSEC3 matching the queried name is returned.  Anything more would hand
every querier NSEC3 hashes it did not ask about, ie, offline zone walking,
which is the thing NSEC3 exists to prevent.

The owner hashes are recomputed per query from the zone's `NSEC3PARAM`, so
zones whose iteration count exceeds 150 (RFC 5155 §A.1's useful maximum; RFC
9276 deprecates anything above 0) are not proved at all rather than allowed to
spend the event loop thread's time.  Zones signed with a hash algorithm other
than SHA-1, or with no NSEC3 records, likewise get an `SOA`-only authority
section.  If the proof does not fit in the answer size (see below), the answer
is sent truncated rather than with a partial (and therefore useless) proof.

## Delegations

A served zone may delegate names below its apex, with an `NS` RRset there.
The zone is not authoritative for anything at or below such a zone cut,
apart from the `DS` RRset at the cut, so queries for those names are not
answered from the zone text, whatever it has there (glue, or records the
delegation occludes).  They get a referral instead (RFC 1034 4.3.2): no `AA`
bit, an empty answer section, the cut's `NS` RRset in the authority section
with, for a `DO` querier, the signed `DS` RRset or the signed `NSEC3`
proving there is none (RFC 5155 7.2.7), and the addresses the zone has for
the name servers in the additional section.  A query for the `DS` at the
cut is answered authoritatively.

When several served zones enclose a query name, the closest one answers it,
so a parent zone served alongside a child it delegates to does not answer
for the child's names.

## UDP Answer Size and Rate Limiting

A UDP query's source address is whatever the sender wrote in it, so an
authoritative server is a candidate reflector: a small spoofed query draws a
larger, DNSSEC-signed answer towards the victim whose address was forged.
The plugin bounds both how big and how many such answers can be.

**Answer size.**  A UDP answer is at most as large as the querier's EDNS0
payload size, but never more than 1232 bytes however large a size it
advertises, so it is never fragmented (DNS Flag Day 2020, RFC 9715).
Without EDNS0, the limit is 512 bytes, as it also is for an advertised size
below 512 (RFC 6891 6.2.5).  The plugin's own OPT advertises 1232.  An
answer that does not fit whole is sent as just the header and question with
`TC` set (and the OPT, to an EDNS0 querier): never a partial RRset, proof or
referral.  The querier retries over TCP, where the answer is sent whole (up
to the plugin's 4096-byte TCP buffer).

**Rate limiting.**  Each source network prefix, by default the /24 for IPv4
(including v4-mapped IPv6 sources) and the /56 for IPv6, has a budget of
UDP answers: a token bucket holding up to `rrl-burst` answers, refilled at
`rrl-responses-per-second`.  The budget is checked when the query arrives,
before anything is looked up for it.  While the prefix has budget, its
queries are answered as usual.  Over budget, every `rrl-slip`th query gets
an empty `TC` answer (header and question only), so a real resolver sharing
the prefix still gets through by retrying over TCP, and the rest get no
answer at all.  TCP is not limited this way, since its peer address is not
spoofable.  A spoofed flood towards one victim therefore reflects at most
that budget, plus header-and-question-sized truncated answers.

Up to `rrl-table-size` prefixes are tracked at a time; when the table is
full, the one heard from least recently is forgotten (and starts with a full
budget if it is heard from again).  What was limited is logged once a
minute in aggregate at `notice` level, never per packet, eg

```
rate limiting: in the last 60s, 3 source prefixes went over 50 answers/s, 1840 answers dropped, 920 sent truncated
```

There is no DNS cookie (RFC 7873) support yet, which would let a validated
source be exempted.

## Per-vhost Options (PVO)

The plugin is configured by Per-Vhost Options on the `protocol-lws-auth-dns`
entry of the vhost's protocol list.  **The entry itself must be present**:
if the vhost has no `ws-protocols` entry for `protocol-lws-auth-dns`, the
protocol receives no options at init and does nothing at all on that vhost —
no UDP sockets are bound and nothing is logged.

| PVO Name   | Description |
| ---------- | ----------- |
| `zone-dir` | **Required.** Absolute path of the directory holding locally-served zone files.  It is scanned once at vhost initialization; only files matching the trust policy below are loaded.  The directory must exist and pass the ownership / mode checks below even if all zones will come from the DHT.  If this PVO is missing the protocol refuses to start (there is no default: an earlier default of shared `/tmp/lws-auth-dns` allowed any local user to inject authoritative zones and was removed). |
| `cache-max-zones` | Optional. Maximum number of DHT-fetched zones held in the in-memory LRU cache. Defaults to 1000. When reached, the least recently queried of them are evicted. Zones from `zone-dir` are always held and are not counted. |
| `rrl-responses-per-second` | Optional. UDP answers per second each source network prefix may receive, see "UDP Answer Size and Rate Limiting".  Defaults to 50, at most 100000.  `0` disables the rate limiting (logged at `warn` level at init). |
| `rrl-burst` | Optional. How many UDP answers a source prefix may receive at once, ie, the size of its token bucket.  Defaults to twice `rrl-responses-per-second`, at most 100000. |
| `rrl-slip` | Optional. Over budget, every this many queries one gets an empty `TC` answer instead of none, so real resolvers retry over TCP.  Defaults to 2, at most 100; `0` drops them all, `1` answers every one with `TC`. |
| `rrl-ipv4-prefix` | Optional. The IPv4 prefix length that is one source, 8 - 32.  Defaults to 24. |
| `rrl-ipv6-prefix` | Optional. The IPv6 prefix length that is one source, 16 - 128.  Defaults to 56. |
| `rrl-table-size` | Optional. How many source prefixes are tracked at once, 1 - 1048576.  Defaults to 4096. |

An `rrl-*` value out of range makes the protocol refuse to start, rather than
quietly run without the limiting the operator asked for.

| `dht-max-pending` | Optional. Maximum number of *distinct domains* per vhost whose queries may be suspended awaiting a DHT fetch. Defaults to 128. There are additional fixed limits of 16 distinct domains and 64 queries per source address, and 1024 pending queries in total. When any limit is reached, new queries needing a DHT fetch are answered `REFUSED` immediately rather than queued. |
| `dnsbl` | Optional. Comma-separated list of DNSBL zones (eg, `zen.spamhaus.org,test.local`). When set, the queried name and the IPs in the answer are checked asynchronously against every listed DNSBL before the response is sent; a positive (listed) result suppresses the answer and is cached for 5 minutes. |

The DNSBL lookups are deduplicated by queried name while they are in flight
(a repeat of a name whose lookups have not completed is dropped rather than
issuing a second set of up to 16 targets × 16 DNSBLs outbound queries), and at
most 256 queries may be suspended on DNSBL lookups at a time; beyond that
further queries are answered `REFUSED`.

## Zone Directory Trust Policy

Everything loaded from `zone-dir` is served as **authoritative** data, so the
directory must be under the exclusive control of the account the plugin
initializes as.
At `PROTOCOL_INIT` the plugin fails closed (refuses to start, logging at
`err` level) unless `zone-dir`:

 - exists and is a real directory (not a symlink to one),
 - is owned by the process's **effective uid at protocol init time**, and
 - is not group- or world-writable.

Individual zone files are additionally only admitted from the scan when they

 - are named in the decorated `<origin>_<ttl-expiry>_<sig-expiry>_<serial>.zone`
   shape the plugin itself labels its cache entries with, where the origin is
   a presentation-format DNS name (labels of `[A-Za-z0-9-]`, no underscores,
   since `_` separates the decorator fields) and the three numeric fields are
   the zone's TTL expiry and RRSIG expiry as unix times and the SOA serial;
   eg, `example.com_2000000000_2000000000_1.zone`,
 - are regular files owned by the same uid and not symlinks, and
 - are not group- or world-writable.

Files that do not meet these conditions are skipped with a `notice` in the
log (`ignoring zone file with foreign name ...` or `refusing foreign or
group/world-writable zone file ...`).  Hand-placed files named simply
`example.com.zone` are therefore **not** loaded; rename them into the
decorated shape.

### Which uid is "the effective uid"

Protocol initialization runs before lws drops privileges.  Under `lwsws`, that
means the checks are made against the uid lwsws was **started** as — normally
root under systemd — and not against the `uid` / `gid` in the lwsws config.
So for a systemd-started lwsws the directory and any local zone files must be
owned by root (`root:root`, dir `0755`, files `0644`, or stricter), regardless
of the account lwsws later drops to.  A directory chowned to the service
account fails the check.

The plugin only reads `zone-dir`, at init, so it does not matter that the
account it drops to cannot write there.  DHT-fetched zones are never written
to disk, so DHT-fed operation is unaffected.

## Logging

A DNS label may contain any octet, including newlines and terminal escapes, so
every wire-derived name is passed through `lws_json_purify()` before it reaches
a log line.  Per-query lines are at `info` level, so an unauthenticated peer
cannot drive the operator's log volume at the default `notice` level.

At startup, a healthy vhost logs one `bound to ipv4 udp port N` and (with IPv6
built) one `bound to ipv6 udp port N` line at `notice` level.  Each zone file
admitted from the scan is logged at `info` level (`Parsed zone ...`); only
rejected files are logged at `notice`.

## Example `lwsws` Configuration

The vhost defines the listening port.  `apply-listen-accept` makes core adopt
every accepted TCP connection on that port as `raw-skt` with the plugin
protocol, so DNS over TCP is served alongside the plugin's own UDP sockets.
Add the `lws-dht-dnssec` protocol to the same vhost to also serve zones fetched
from the DHT.

```json
{
	"vhosts": [{
		"name": "auth-dns",
		"port": 53,
		"ciphers": "",
		"listen-accept-role": "raw-skt",
		"listen-accept-protocol": "protocol-lws-auth-dns",
		"apply-listen-accept": "1",
		"ws-protocols": [{
			"protocol-lws-auth-dns": {
				"status": "ok",
				"zone-dir": "/etc/lws-auth-dns/zones",
				"cache-max-zones": "1000",
				"dht-max-pending": "16"
			}
		}]
	}]
}
```

and, once, as root:

```
mkdir -p /etc/lws-auth-dns/zones
chown root:root /etc/lws-auth-dns/zones
chmod 0755 /etc/lws-auth-dns/zones
```

For a non-lwsws application, set `info.listen_accept_role = "raw-skt"`,
`info.listen_accept_protocol = "protocol-lws-auth-dns"` and either
`LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG` (every accepted
connection is raw DNS) or `LWS_SERVER_OPTION_FALLBACK_TO_APPLY_LISTEN_ACCEPT_CONFIG`
(only connections that do not parse as HTTP / TLS) on the vhost, and pass
the PVOs on the `protocol-lws-auth-dns` entry of `info.pvo`;
`minimal-examples-lowlevel/api-tests/api-test-dns-server` is a worked example.

## Troubleshooting

**No answers, nothing logged per query.**  Check what is bound:

```
ss -ulnp | grep ':53 '
ss -tlnp | grep ':53 '
```

A working vhost shows UDP sockets on `0.0.0.0:53` and `[::]:53` owned by the
lws process as well as the TCP listener.  If the TCP listener is there but the
UDP sockets are not, `PROTOCOL_INIT` did not complete: core creates the TCP
listener unconditionally, but the UDP sockets are only bound by the plugin once
its init has passed the policy checks.  In that state UDP queries reach no
socket at all, and TCP queries are closed without a log line because there is
no per-vhost state to serve them from.

The reason is logged once, at startup, so look there rather than while sending
queries:

```
journalctl -u lwsws -b | grep -iE 'zone.dir|failed init|foreign name|bound to ipv'
```

 - `the "zone-dir" pvo is required, refusing to start` — add the PVO.
 - `zone dir ... cannot be opened` / `is not a service-owned,
   non-group/world-writable directory` — fix existence, ownership (see
   "Which uid" above) and mode.
 - `protocol protocol-lws-auth-dns failed init` (from core) accompanies either
   of the above.
 - No plugin log lines at all — the vhost has no `ws-protocols` entry for
   `protocol-lws-auth-dns`, so the protocol was never given its options.

**Zone loaded from disk but not served / "ignoring zone file with foreign
name".**  The filename is not in the decorated shape, or the file is not owned
by the init-time uid, or is group/world-writable.

**Zone not loaded, "line N: ..." in the log.**  The zone text has a name or
field auth-dns refuses (see the zone file syntax above); the message names
the logical line and what is wrong with it.

**Zone file present but "has expired, not loading it" at startup.**  The
`<ttl-expiry>` or `<sig-expiry>` field in the filename is in the past; regenerate
the zone (and its filename) with a current signing.  The expired file is left
where it is.

