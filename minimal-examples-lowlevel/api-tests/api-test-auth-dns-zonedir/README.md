# lws-api-test-auth-dns-zonedir

Fence for security-audit finding F-055: the local zone-dir trust policy in
the authoritative-DNS plugin (`protocol-lws-auth-dns`), and for G-117: the
zones it is handed by `lws-dht-dnssec` are installed only as the domain they
were verified for.

Everything the plugin loads from its zone dir is served as **authoritative**
DNS data, and expired / evicted entries are unlinked from that dir by
filename.  Pre-fix, a missing `zone-dir` pvo silently defaulted to shared
`/tmp/lws-auth-dns` and the init dir-scan trusted any `*.zone` file on
syntax alone — no ownership, permission, or name-shape check — so any local
user who pre-created or owned the directory could inject zones and have
victim zone files unlinked.

The test builds the plugin in statically and runs sequential phases, each
with its own context and port, planting the attack arrangements on disk
first (all fixture modes are chmod'd explicitly so they do not depend on
the process umask):

| phase | arrangement | pre-fix behavior | post-fix behavior |
|-------|-------------|------------------|-------------------|
| 1 | service-owned dir + properly decorated `origin_ttl_sig_serial.zone` file | served | served (control that the happy path still works) |
| 2 | no `zone-dir` pvo at all | defaulted to `/tmp/lws-auth-dns` and started (listener up) | protocol init refused: queries stay unanswered and the UDP port is bindable by the test itself |
| 3 | world-writable (0777) zone dir with a planted zone | planted zone served | init refused, no listener |
| 4 | `zone-dir` that is a symlink to a valid dir | followed for the dir checks; started anyway (listener up, answering) | init refused, no listener |
| 5 | good dir, but undecorated-name / two-field-suffix / group-writable (0666) / symlinked zone files | all loaded and served | only the properly shaped file loads; the rest answer REFUSED (rcode 5) while the control zone still answers |
| 6 | zones handed over by `lws-dht-dnssec` as verified for a domain (G-117): one with a trailing `$ORIGIN` for a zone the dir serves, one wholly that other zone, and a control that is its domain's own | installed under their last `$ORIGIN`, replacing the served zone | only the control is installed; the served zone answers as before and the payloads' names do not exist |
| 7 | a query for a zone nobody serves, whose fetch from `lws-dht-dnssec` never answers (G-224) | the query timed out (REFUSED after 5s) but its fetch was left running, holding auth-dns' opaque | when the query times out the fetch is given up: completed exactly once, as timed out, and nothing holds the opaque |
| 8 | *(root only)* zone file owned by another uid | loaded and served | file ignored (REFUSED) while the service-owned control file in the same dir still answers |
| 9 | *(root only)* zone dir owned by another uid | started | init refused, no listener |

"No listener" is asserted both by silence (no response within the window)
and by the test binding the UDP port itself afterwards — the plugin only
creates its UDP listeners once its protocol init succeeded.

Phase 6 stands in for `lws-dht-dnssec` with a protocol of that name on the
vhost, whose ops only collect the callback auth-dns registers for verified
zones; the test then hands it the payloads as the plugin does.

Phase 7 stands in for the zone fetches too, keeping to the `fetch_zone()`
contract in `lws-dht-dnssec.h` (merge, cancel without completion, fail with
one completion as timed out) and never answering.

Phases 8-9 need to create files/dirs owned by another uid and are skipped
when the test is not running as root.

## Commandline

| option | meaning |
|--------|---------|
| `-p PORT` | first auth dns port (from `lws_get_free_port()`) |
| `-b PORT` | second auth dns port (phases alternate between the ports) |

The planted fixtures are (re)created under a per-run scratch dir
`zones-f055/<pid>` in the working directory (so runs under different uids
cannot trip over each other's leftovers) and removed again at exit; the
whole test takes about ten seconds.
